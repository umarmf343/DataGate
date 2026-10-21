using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace DataGate {
 public class TrafficSample { public long Download; public long Upload; public double DownloadRate; public double UploadRate; }
 public sealed class TrafficBook {
  readonly object sync=new object();
  readonly Dictionary<string,TrafficSample> totals=new Dictionary<string,TrafficSample>(StringComparer.OrdinalIgnoreCase);
  readonly Dictionary<string,TrafficSample> previous=new Dictionary<string,TrafficSample>(StringComparer.OrdinalIgnoreCase);
  readonly Stopwatch watch=Stopwatch.StartNew(); double last;
  public void Add(string path,long size,bool send){if(String.IsNullOrEmpty(path)||size<0)return;lock(sync){TrafficSample t;if(!totals.TryGetValue(path,out t))totals[path]=t=new TrafficSample();if(send)t.Upload+=size;else t.Download+=size;}}
  public Dictionary<string,TrafficSample> Snapshot(){lock(sync){double now=watch.Elapsed.TotalSeconds,seconds=Math.Max(.05,now-last);var result=new Dictionary<string,TrafficSample>(StringComparer.OrdinalIgnoreCase);foreach(var p in totals){TrafficSample old;if(!previous.TryGetValue(p.Key,out old))old=new TrafficSample();result[p.Key]=new TrafficSample{Download=p.Value.Download,Upload=p.Value.Upload,DownloadRate=Math.Max(0,p.Value.Download-old.Download)/seconds,UploadRate=Math.Max(0,p.Value.Upload-old.Upload)/seconds};previous[p.Key]=new TrafficSample{Download=p.Value.Download,Upload=p.Value.Upload};}last=now;return result;}}
 }
 public sealed class TrafficMonitor : IDisposable {
  readonly object gate=new object();readonly Dictionary<int,string> paths=new Dictionary<int,string>();readonly Dictionary<int,DateTime> expires=new Dictionary<int,DateTime>();
  readonly TrafficBook book=new TrafficBook();Task pump;volatile bool stopping;ulong session,consumer;IntPtr properties,loggerName;string sessionName;
  EventCallback callback;BufferCallback bufferCallback;
  static readonly Guid Tcp=new Guid("9a280ac0-c8e0-11d1-84e2-00c04fb998a2"),Udp=new Guid("bf3a50c5-a9c9-4988-a005-2df0b7c80f80"),ProcessProvider=new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c");
  [StructLayout(LayoutKind.Sequential)] struct Wnode {public uint BufferSize,ProviderId;public ulong HistoricalContext;public long TimeStamp;public Guid Guid;public uint ClientContext,Flags;}
  [StructLayout(LayoutKind.Sequential)] struct Properties {public Wnode Wnode;public uint BufferSize,MinimumBuffers,MaximumBuffers,MaximumFileSize,LogFileMode,FlushTimer,EnableFlags;public int AgeLimit;public uint NumberOfBuffers,FreeBuffers,EventsLost,BuffersWritten,LogBuffersLost,RealTimeBuffersLost;public IntPtr LoggerThreadId;public uint LogFileNameOffset,LoggerNameOffset;}
  // Windows x64 EVENT_TRACE_LOGFILEW. Build is deliberately x64; validate layout in self-tests.
  [StructLayout(LayoutKind.Explicit,Size=448)] struct Logfile {
   [FieldOffset(8)] public IntPtr LoggerName;
   [FieldOffset(28)] public uint ProcessTraceMode;
   [FieldOffset(400)] public IntPtr BufferCallback;
   [FieldOffset(424)] public IntPtr EventRecordCallback;
  }
  [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void EventCallback(IntPtr record);
  [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate uint BufferCallback(IntPtr logfile);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern uint StartTraceW(out ulong handle,string name,IntPtr properties);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern uint ControlTraceW(ulong handle,string name,IntPtr properties,uint code);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern ulong OpenTraceW(ref Logfile logfile);
  [DllImport("advapi32.dll")] static extern uint ProcessTrace([In] ulong[] handles,uint count,IntPtr start,IntPtr end);
  [DllImport("advapi32.dll")] static extern uint CloseTrace(ulong handle);
  public volatile string Status="Live app usage needs administrator approval";
  public bool Running {get;private set;}
  public long UnattributedBytes;
  public void Start(){
   if(!Firewall.Admin){Status="Live app usage needs administrator approval";return;}
   try {
    ValidateLayout();sessionName="DataGate.Traffic."+Process.GetCurrentProcess().Id+"."+Guid.NewGuid().ToString("N");
    int size=Marshal.SizeOf(typeof(Properties));properties=Marshal.AllocHGlobal(size+1024);for(int i=0;i<size+1024;i++)Marshal.WriteByte(properties,i,0);
    var config=new Properties{Wnode=new Wnode{BufferSize=(uint)(size+1024),Guid=Guid.NewGuid(),ClientContext=1,Flags=0x00020000},BufferSize=64,MinimumBuffers=8,MaximumBuffers=64,LogFileMode=0x02000100,FlushTimer=1,EnableFlags=0x00010001,LoggerNameOffset=(uint)size};
    Marshal.StructureToPtr(config,properties,false);uint error=StartTraceW(out session,sessionName,properties);if(error!=0)throw new Win32Exception((int)error);
    callback=OnEvent;bufferCallback=p=>{uint lost=unchecked((uint)Marshal.ReadInt32(p,416));if(lost>0)Status="LIVE (approximate): Windows dropped "+lost+" events";return stopping?0u:1u;};
    loggerName=Marshal.StringToHGlobalUni(sessionName);var log=new Logfile{LoggerName=loggerName,ProcessTraceMode=0x10000100,EventRecordCallback=Marshal.GetFunctionPointerForDelegate(callback),BufferCallback=Marshal.GetFunctionPointerForDelegate(bufferCallback)};
    consumer=OpenTraceW(ref log);if(consumer==UInt64.MaxValue)throw new Win32Exception(Marshal.GetLastWin32Error());
    Running=true;Status="LIVE: observed TCP/UDP, IPv4 + IPv6 (includes LAN)";
    pump=Task.Factory.StartNew(()=>{try{uint result=ProcessTrace(new[]{consumer},1,IntPtr.Zero,IntPtr.Zero);if(!stopping){Running=false;Status="Live capture stopped ("+result+"); values are incomplete";}}catch(Exception e){if(!stopping){Running=false;Status="Live capture unavailable: "+e.Message;}}},TaskCreationOptions.LongRunning);
   }catch(Exception e){Status="Live capture unavailable: "+e.Message;Running=false;Dispose();}
  }
  void OnEvent(IntPtr record){try{Guid provider=(Guid)Marshal.PtrToStructure(IntPtr.Add(record,24),typeof(Guid));byte version=Marshal.ReadByte(record,42),opcode=Marshal.ReadByte(record,45);int length=(ushort)Marshal.ReadInt16(record,86);IntPtr data=Marshal.ReadIntPtr(record,96);
   if(provider==ProcessProvider && (opcode==1 || opcode==2) && length>=12){int pid=Marshal.ReadInt32(data,8);lock(gate){paths.Remove(pid);expires.Remove(pid);}return;}
   if((provider!=Tcp && provider!=Udp)||version<2||length<8||(opcode!=10 && opcode!=11 && opcode!=26 && opcode!=27))return;
   Count(Marshal.ReadInt32(data,0),unchecked((uint)Marshal.ReadInt32(data,4)),opcode==10 || opcode==26);
  }catch{/* Never let an event parser exception cross the native callback boundary. */}}
  void Count(int pid,long size,bool send){string path=null;lock(gate){DateTime expiry;if(!paths.TryGetValue(pid,out path)||!expires.TryGetValue(pid,out expiry)||expiry<DateTime.UtcNow){try{using(var p=Process.GetProcessById(pid))path=p.MainModule.FileName;}catch{path=null;}paths[pid]=path;expires[pid]=DateTime.UtcNow.AddSeconds(2);}}if(path==null)Interlocked.Add(ref UnattributedBytes,size);else book.Add(path,size,send);}
  public Dictionary<string,TrafficSample> Snapshot(){return book.Snapshot();}
  public static void ValidateLayout(){if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(Wnode))!=48 || Marshal.SizeOf(typeof(Properties))!=120 || Marshal.SizeOf(typeof(Logfile))!=448)throw new PlatformNotSupportedException("Live monitoring requires Windows x64 with the expected ETW structure layout.");}
  public void Dispose(){stopping=true;Running=false;if(session!=0){ControlTraceW(session,sessionName,properties,1);session=0;}if(consumer!=0 && consumer!=UInt64.MaxValue){CloseTrace(consumer);consumer=0;}if(pump!=null && !pump.IsCompleted){try{pump.Wait(3000);}catch{}}if(pump==null || pump.IsCompleted){if(properties!=IntPtr.Zero){Marshal.FreeHGlobal(properties);properties=IntPtr.Zero;}if(loggerName!=IntPtr.Zero){Marshal.FreeHGlobal(loggerName);loggerName=IntPtr.Zero;}}}
 }
}
