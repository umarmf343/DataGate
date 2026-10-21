using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace DataGate {
 public sealed class RelatedCandidate {public string Path;public string Reason;public bool Blocked;public override string ToString(){return (Blocked?"[BLOCKED] ":"")+System.IO.Path.GetFileName(Path)+" — "+Reason+" — "+Path;}}
 public static class RelatedApps {
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct Entry {public uint Size,Usage,Pid;public IntPtr Heap;public uint Module,Threads,Parent;public int Priority;public uint Flags;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)]public string Exe;}
  [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool Process32FirstW(IntPtr snapshot,ref Entry entry);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern bool Process32NextW(IntPtr snapshot,ref Entry entry);
  [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
  public static string SafeRoot(string path){
   string folder=System.IO.Path.GetDirectoryName(Firewall.Normalize(path));
   string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows)+"\\";
   if(folder.StartsWith(windows,StringComparison.OrdinalIgnoreCase))return null;
   var roots=new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Programs"),Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)};
   foreach(string root in roots)if(folder.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase)){
    string relative=folder.Substring(root.Length+1);string[] parts=relative.Split('\\');
    if(parts.Length==0 || parts[0].Equals("Temp",StringComparison.OrdinalIgnoreCase) || parts[0].Equals("Microsoft",StringComparison.OrdinalIgnoreCase) && parts.Length<2 || parts[0].Equals("Packages",StringComparison.OrdinalIgnoreCase))return null;
    // Keep vendor-wide directories out: choose the executable's own application folder, never an entire vendor.
    string leaf=System.IO.Path.GetFileName(folder);if((leaf.Equals("bin",StringComparison.OrdinalIgnoreCase)||leaf.Equals("Application",StringComparison.OrdinalIgnoreCase)||leaf.StartsWith("app-",StringComparison.OrdinalIgnoreCase)) && parts.Length>1)folder=System.IO.Path.GetDirectoryName(folder);
    if(folder.Equals(root,StringComparison.OrdinalIgnoreCase))return null;
    return folder;
   }
   return null;
  }
  public static List<RelatedCandidate> Discover(string selected,IEnumerable<AppRow> known){
   selected=Firewall.Normalize(selected);string root=SafeRoot(selected);var managed=Firewall.ManagedApps();var candidates=new Dictionary<string,RelatedCandidate>(StringComparer.OrdinalIgnoreCase);
   Action<string,string> add=(path,reason)=>{try{path=Firewall.Normalize(path);if(path.Equals(selected,StringComparison.OrdinalIgnoreCase)||!File.Exists(path)||!path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))return;if(!candidates.ContainsKey(path))candidates[path]=new RelatedCandidate{Path=path,Reason=reason,Blocked=managed.ContainsKey(path)&&managed[path]=="Blocked"};}catch{}};
   if(root!=null){foreach(var row in known)if(row.Path.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase))add(row.Path,"same application folder");
    var folders=new Queue<Tuple<string,int>>();folders.Enqueue(Tuple.Create(root,0));int scanned=0;
    while(folders.Count>0 && scanned++<120 && candidates.Count<100){var f=folders.Dequeue();try{foreach(string exe in Directory.GetFiles(f.Item1,"*.exe"))add(exe,"installation-folder candidate (not a proven dependency)");if(f.Item2<3)foreach(string dir in Directory.GetDirectories(f.Item1)){string name=System.IO.Path.GetFileName(dir);if(name=="node_modules"||name==".git"||(File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0)continue;folders.Enqueue(Tuple.Create(dir,f.Item2+1));}}catch{}}
   }
   var parent=new Dictionary<uint,uint>();var paths=new Dictionary<uint,string>();IntPtr snapshot=CreateToolhelp32Snapshot(2,0);
   if(snapshot!=new IntPtr(-1)){try{var e=new Entry{Size=(uint)Marshal.SizeOf(typeof(Entry))};if(Process32FirstW(snapshot,ref e))do{parent[e.Pid]=e.Parent;}while(Process32NextW(snapshot,ref e));}finally{CloseHandle(snapshot);}}
   foreach(uint pid in parent.Keys)try{using(var p=Process.GetProcessById((int)pid))paths[pid]=p.MainModule.FileName;}catch{}
   var selectedPids=new HashSet<uint>(paths.Where(p=>String.Equals(p.Value,selected,StringComparison.OrdinalIgnoreCase)).Select(p=>p.Key));
   foreach(var pair in paths){uint current=pair.Key;var visited=new HashSet<uint>();while(parent.ContainsKey(current)&&visited.Add(current)){current=parent[current];if(selectedPids.Contains(current)){add(pair.Value,"running descendant process (may be independently launched)");break;}}}
   return candidates.Values.OrderByDescending(c=>c.Blocked).ThenBy(c=>c.Path).ToList();
  }
 }
 public sealed class RelatedDialog:Form {
  readonly CheckedListBox list=new CheckedListBox();readonly List<RelatedCandidate> candidates;
  public string[] Chosen {get{return list.CheckedIndices.Cast<int>().Select(i=>candidates[i].Path).ToArray();}}
  public RelatedDialog(List<RelatedCandidate> items){candidates=items;Text="Review related executables — no changes yet";Size=new System.Drawing.Size(940,510);MinimumSize=new System.Drawing.Size(700,400);StartPosition=FormStartPosition.CenterParent;Font=new System.Drawing.Font("Segoe UI",10);
   var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(16),RowCount=3};layout.RowStyles.Add(new RowStyle(SizeType.Absolute,78));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,48));Controls.Add(layout);
   layout.Controls.Add(new Label{Dock=DockStyle.Fill,Text="Select the helpers you want to include, then add them to the dashboard's checked list. This does NOT change access yet.\nCandidates are folder/process relationships, not guaranteed dependencies. Avoid approving shared runtimes or Windows services broadly. A blocked helper can explain why an allowed app still cannot connect."});
   list.Dock=DockStyle.Fill;list.CheckOnClick=true;list.HorizontalScrollbar=true;foreach(var item in items)list.Items.Add(item,false);layout.Controls.Add(list);
   var buttons=new FlowLayoutPanel{Dock=DockStyle.Fill};var add=new Button{Text="Add chosen to checked list",AutoSize=true,DialogResult=DialogResult.OK};buttons.Controls.Add(add);buttons.Controls.Add(new Button{Text="Cancel",AutoSize=true,DialogResult=DialogResult.Cancel});layout.Controls.Add(buttons);AcceptButton=add;CancelButton=(Button)buttons.Controls[1];
  }
 }
}
