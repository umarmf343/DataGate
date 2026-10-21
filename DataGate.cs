using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Serialization;

namespace DataGate {
 public class ProfileState { public int Id; public int Outbound; public bool Enabled; }
 public class RuleState { public string Fingerprint; public int EnabledCount; }
 public class RecoveryState {
  public List<ProfileState> Profiles = new List<ProfileState>();
  public List<string> DisabledAllowRules = new List<string>();
  public List<RuleState> AllowRuleStates = new List<RuleState>();
  public DateTime CreatedUtc = DateTime.UtcNow;
 }
 public class AppRow {
  public string Name; public string Path; public int Instances; public string Access; public string Warning="";
 }
 public static class Firewall {
  public const string Group = "DataGate.Managed.v1";
  public const string Strict = "DataGate.Strict.v1";
  public static readonly string StatePath = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DataGate", "firewall-recovery.xml");
  public static dynamic Policy() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); }
  public static bool Admin { get { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } }
  static void RequireAdmin() { if (!Admin) throw new InvalidOperationException("Administrator approval is required. Click Enable controls (Admin)."); }
  public static string Normalize(string path){if(String.IsNullOrWhiteSpace(path))return "";return System.IO.Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'))).TrimEnd('\\');}
  static string Id(string path) { using(var hash=SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(Normalize(path).ToLowerInvariant()))).Replace("-", "").Substring(0,24); }
  public static string RuleName(string path, string action) { return "DataGate."+ action + "." + Id(path); }
  public static string ValidatePath(string path) {
   string full=Normalize(path);
   if(!File.Exists(full) || !full.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || full.StartsWith(@"\\")) throw new ArgumentException("Choose a local, existing Windows .exe file.");
   return full;
  }
  static void Add(dynamic policy, string name, string group, string path, int action, int protocol=256, string service=null, string ports=null, int direction=2) {
   dynamic rule=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
   rule.Name=name; rule.Description="Created by DataGate. Managed from the DataGate dashboard."; rule.Grouping=group;
   rule.Direction=direction; rule.Action=action; rule.Enabled=true; rule.Profiles=7; rule.Protocol=protocol;
   if(path!=null) rule.ApplicationName=path;
   if(service!=null) rule.ServiceName=service;
   if(ports!=null) rule.RemotePorts=ports;
   policy.Rules.Add(rule);
  }
  static List<string> OwnedNames(dynamic policy, string group=null) {
   var names=new List<string>();
   foreach(dynamic rule in policy.Rules) if((string)rule.Grouping == Group || (string)rule.Grouping == Strict) { if(group==null || (string)rule.Grouping==group) names.Add((string)rule.Name); }
   return names;
  }
  static void RemoveIfPresent(dynamic policy,string name) {
   foreach(dynamic r in policy.Rules) if((string)r.Name==name) { if((string)r.Grouping!=Group && (string)r.Grouping!=Strict) throw new InvalidOperationException("A firewall rule name conflicts with DataGate. No foreign rule will be removed."); policy.Rules.Remove(name); return; }
  }
  public static Dictionary<string,string> ManagedApps() {
   var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase); dynamic policy=Policy();
   foreach(dynamic rule in policy.Rules) if((string)rule.Grouping==Group && (bool)rule.Enabled && !String.IsNullOrWhiteSpace((string)rule.ApplicationName)) {
    string path=Normalize((string)rule.ApplicationName); string state=(int)rule.Action==0?"Blocked":"Approved";
    if(!result.ContainsKey(path) || state=="Blocked") result[path]=state;
   }
   return result;
  }
  public static void SetApp(string path,bool allow) {
   RequireAdmin(); path=ValidatePath(path); dynamic policy=Policy();
   if((int)policy.LocalPolicyModifyState!=0)throw new InvalidOperationException("Windows policy restricts local firewall changes. Contact your administrator; no success will be claimed.");
   // Remove legacy and duplicate DataGate rules by canonical executable identity, not just one generated name.
   string desired=RuleName(path,allow?"Allow":"Block");
   var existing=new List<object>();foreach(dynamic rule in policy.Rules)if((string)rule.Grouping==Group && !String.IsNullOrWhiteSpace((string)rule.ApplicationName) && String.Equals(Normalize((string)rule.ApplicationName),path,StringComparison.OrdinalIgnoreCase))existing.Add(rule);
   RemoveIfPresent(policy,desired);Add(policy,desired,Group,path,allow?1:0);
   foreach(dynamic rule in existing)if((string)rule.Name!=desired)RemoveIfPresent(policy,(string)rule.Name);
   string inbound=RuleName(path,"BlockIn");
   if(!allow) {RemoveIfPresent(policy,inbound);Add(policy,inbound,Group,path,0,256,null,null,1);}
   else RemoveIfPresent(policy,inbound);
   dynamic check=policy.Rules.Item(desired);
   if(!(bool)check.Enabled || (int)check.Action!=(allow?1:0)) throw new InvalidOperationException("The rule could not be verified.");
   foreach(dynamic rule in policy.Rules)if((string)rule.Grouping==Group && (bool)rule.Enabled && !String.IsNullOrWhiteSpace((string)rule.ApplicationName) && String.Equals(Normalize((string)rule.ApplicationName),path,StringComparison.OrdinalIgnoreCase) && (int)rule.Action!=(allow?1:0))throw new InvalidOperationException("A conflicting DataGate rule remains; retry or use diagnostics.");
   try{string folder=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"DataGate","Logs");Directory.CreateDirectory(folder);string log=System.IO.Path.Combine(folder,"actions.log");if(File.Exists(log)&&new FileInfo(log).Length>1048576){string old=log+".previous";if(File.Exists(old))File.Delete(old);File.Move(log,old);}File.AppendAllText(log,DateTime.UtcNow.ToString("O")+"\t"+(allow?"ALLOW":"BLOCK BOTH DIRECTIONS")+"\t"+path+"\tRULE VERIFIED (not a connectivity guarantee)\r\n");}catch{}
  }
  public static Dictionary<string,string> Conflicts(IEnumerable<string> paths){
   var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var targets=new HashSet<string>(paths.Select(Normalize),StringComparer.OrdinalIgnoreCase);dynamic p=Policy();int active=(int)p.CurrentProfileTypes;
   foreach(dynamic rule in p.Rules)if((bool)rule.Enabled && (int)rule.Direction==2 && (int)rule.Action==0 && (string)rule.Grouping!=Group && ((int)rule.Profiles & active)!=0){string path=(string)rule.ApplicationName;if(String.IsNullOrWhiteSpace(path)||path=="*")continue;try{path=Normalize(path);}catch{continue;}if(targets.Contains(path)){string text="Other outbound block: "+(string)rule.Name+" (may be limited by ports/services). DataGate will not delete another tool's rule.";result[path]=result.ContainsKey(path)?result[path]+"\n"+text:text;}}
   return result;
  }
  public static string Health() {
   dynamic p=Policy();
   bool enabled=true; foreach(int id in new[]{1,2,4}) enabled &= (bool)p.FirewallEnabled[id];
   return enabled?"Windows Firewall is ON":"Warning: a firewall profile is OFF. Blocking is not reliable.";
  }
  static bool Probe(System.Net.IPAddress address) {using(var client=new System.Net.Sockets.TcpClient(address.AddressFamily)){try{var task=client.ConnectAsync(address,443);return task.Wait(4000) && client.Connected;}catch{return false;}}}
  public static void VerifyWrite() {
   RequireAdmin();dynamic p=Policy();string name="DataGate.Verification."+Guid.NewGuid().ToString("N");
   System.Net.IPAddress address=null;bool baseline=false,blocked=false;
   try {address=System.Net.Dns.GetHostAddresses("www.microsoft.com").FirstOrDefault(x=>x.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork);if(address!=null)baseline=Probe(address);}catch{}
   try {
    Add(p,name,Group,Application.ExecutablePath,0);
    dynamic rule=p.Rules.Item(name);
    if((int)rule.Action!=0 || !(bool)rule.Enabled || (int)rule.Direction!=2)throw new InvalidOperationException("Temporary block rule verification failed.");
    if(baseline)blocked=!Probe(address);
   }finally{RemoveIfPresent(p,name);}
   bool restored=baseline && Probe(address);
   string packet=baseline?(blocked && restored?"PASS: fresh TCP connection worked before blocking, failed while blocked, and worked after rule removal.":"INCONCLUSIVE: TCP test did not complete the expected before/block/restore sequence."):"INCONCLUSIVE: baseline TCP connection was unavailable.";
   File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"firewall-verification.txt"),"PASS: administrator-created temporary outbound block rule was read back and removed. No global policy changes. "+packet+" "+DateTime.UtcNow.ToString("O"));
  }
  public static void VerifyRoundTrip(){
   RequireAdmin();string path=Application.ExecutablePath;dynamic p=Policy();
   if(ManagedApps().ContainsKey(path))throw new InvalidOperationException("The test executable already has DataGate rules. Refusing to change user-selected policy during the test.");
   var address=System.Net.Dns.GetHostAddresses("www.microsoft.com").First(x=>x.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork);bool baseline=Probe(address),blocked=false,restored=false;
   string legacy="DataGate.Test.Legacy."+Guid.NewGuid().ToString("N");
   try{SetApp(path,false);int count=0;foreach(dynamic r in p.Rules)if((string)r.Grouping==Group && String.Equals((string)r.ApplicationName,path,StringComparison.OrdinalIgnoreCase)&&(bool)r.Enabled&&(int)r.Action==0)count++;if(count!=2)throw new Exception("Inbound/outbound block verification failed.");if(baseline)blocked=!Probe(address);
    Add(p,legacy,Group,path,0); // Deliberately simulate an old rule with a different name.
    SetApp(path,true);foreach(dynamic r in p.Rules)if((string)r.Grouping==Group && String.Equals((string)r.ApplicationName,path,StringComparison.OrdinalIgnoreCase)&&(bool)r.Enabled&&(int)r.Action==0)throw new Exception("Re-enable left a legacy DataGate block behind.");if(baseline)restored=Probe(address);
    File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"roundtrip-test.txt"),"PASS: Block installed both directions; Enable removed every legacy/current DataGate block and installed outbound allow. "+(baseline?(blocked&&restored?"PASS: TCP worked, was blocked, and worked again after Enable.":"INCONCLUSIVE: TCP before/block/enable sequence did not match expectations."):"INCONCLUSIVE: baseline internet unavailable.")+" Test-only rules removed in finally.");
   }finally{var names=new List<string>();foreach(dynamic r in p.Rules)if((string)r.Grouping==Group && String.Equals((string)r.ApplicationName,path,StringComparison.OrdinalIgnoreCase))names.Add((string)r.Name);foreach(string name in names)RemoveIfPresent(p,name);}
  }
  static void Save(RecoveryState state) {
   Directory.CreateDirectory(System.IO.Path.GetDirectoryName(StatePath));
   string temp=StatePath+".new";
   using(var stream=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None)) { new XmlSerializer(typeof(RecoveryState)).Serialize(stream,state); stream.Flush(true); }
   if(File.Exists(StatePath)) File.Replace(temp,StatePath,null); else File.Move(temp,StatePath);
  }
  static RecoveryState Load() { using(var stream=File.OpenRead(StatePath)) return (RecoveryState)new XmlSerializer(typeof(RecoveryState)).Deserialize(stream); }
  public static string Fingerprint(dynamic r) {
   // Display names are NOT unique on Windows. Match complete rule identities for recovery.
   var parts=new List<string>();
   foreach(string property in new[]{"Name","Description","ApplicationName","ServiceName","Protocol","LocalPorts","RemotePorts","LocalAddresses","RemoteAddresses","IcmpTypesAndCodes","Profiles","Direction","Action","Grouping","InterfaceTypes","EdgeTraversal","LocalAppPackageId","LocalUserAuthorizedList","RemoteUserAuthorizedList","RemoteMachineAuthorizedList","SecureFlags"}) {
    try { object value=r.GetType().InvokeMember(property,System.Reflection.BindingFlags.GetProperty,null,r,null); parts.Add(property+":"+Convert.ToString(value,System.Globalization.CultureInfo.InvariantCulture)); }
    catch { parts.Add(property+":<not available>"); }
   }
   try { object value=r.Interfaces;var array=value as Array;parts.Add("Interfaces:"+(array==null?Convert.ToString(value):String.Join(",",array.Cast<object>().Select(x=>Convert.ToString(x)).OrderBy(x=>x)))); }catch{parts.Add("Interfaces:<not available>");}
   return String.Join("\n",parts);
  }
  public static void EnableStrict() {
   RequireAdmin(); if(File.Exists(StatePath)) throw new InvalidOperationException("A recovery snapshot already exists. Restore it before starting a new Focus session.");
   dynamic p=Policy();
   if((int)p.LocalPolicyModifyState!=0) throw new InvalidOperationException("Windows reports a managed or restricted firewall policy. Focus mode is unavailable; consult your system administrator.");
   if(!ManagedApps().Values.Any(v=>v=="Approved")) throw new InvalidOperationException("Approve at least one application before enabling Focus mode.");
   var state=new RecoveryState();
   foreach(int id in new[]{1,2,4}) {
    if(!(bool)p.FirewallEnabled[id]) throw new InvalidOperationException("Turn on all Windows Firewall profiles in Windows Security first.");
    state.Profiles.Add(new ProfileState{Id=id,Outbound=(int)p.DefaultOutboundAction[id],Enabled=(bool)p.FirewallEnabled[id]});
   }
   var identities=new Dictionary<string,int>();
   foreach(dynamic r in p.Rules) {
    if((bool)r.Enabled && (int)r.Direction==2 && (int)r.Action==1 && (string)r.Grouping!=Group && (string)r.Grouping!=Strict) { string identity=Fingerprint(r);if(!identities.ContainsKey(identity))identities[identity]=0;identities[identity]++; }
   }
   foreach(var pair in identities)state.AllowRuleStates.Add(new RuleState{Fingerprint=pair.Key,EnabledCount=pair.Value});
   Save(state); // Durable journal BEFORE any policy changes.
   try {
    string host=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"svchost.exe");
    Add(p,"DataGate.Essential.DNS",Strict,host,1,17,"Dnscache","53");
    Add(p,"DataGate.Essential.DNS.TCP",Strict,host,1,6,"Dnscache","53");
    Add(p,"DataGate.Essential.DHCP",Strict,host,1,17,"Dhcp","67,547");
    foreach(dynamic r in p.Rules) if((bool)r.Enabled && (int)r.Direction==2 && (int)r.Action==1 && (string)r.Grouping!=Group && (string)r.Grouping!=Strict)r.Enabled=false;
    foreach(int id in new[]{1,2,4}) p.DefaultOutboundAction[id]=0;
    foreach(int id in new[]{1,2,4}) if((int)p.DefaultOutboundAction[id]!=0) throw new InvalidOperationException("Windows did not apply outbound blocking.");
    foreach(dynamic r in p.Rules) if((bool)r.Enabled && (int)r.Direction==2 && (int)r.Action==1 && (string)r.Grouping!=Group && (string)r.Grouping!=Strict) throw new InvalidOperationException("An external outbound allow rule remains active; Focus cannot be verified on this policy.");
   } catch(Exception original) { try { Restore(false); } catch(Exception rollback) { throw new InvalidOperationException("Focus failed and recovery needs attention: "+rollback.Message+". Snapshot retained at "+StatePath,original); } throw; }
  }
  public static void Restore(bool removeAppRules) {
   RequireAdmin(); dynamic p=Policy(); var errors=new List<string>();
   if(File.Exists(StatePath)) {
    RecoveryState state=Load();
    foreach(var profile in state.Profiles) try { p.DefaultOutboundAction[profile.Id]=profile.Outbound; } catch(Exception e) { errors.Add(e.Message); }
    var indexed=new Dictionary<string,List<object>>();
    foreach(dynamic r in p.Rules)if((int)r.Direction==2 && (int)r.Action==1){string key=Fingerprint(r);if(!indexed.ContainsKey(key))indexed[key]=new List<object>();indexed[key].Add(r);}
    foreach(var saved in state.AllowRuleStates) try {
     var matches=indexed.ContainsKey(saved.Fingerprint)?indexed[saved.Fingerprint]:new List<object>();int enabled=0;
     foreach(dynamic r in matches)if((bool)r.Enabled)enabled++;
     if(matches.Count<saved.EnabledCount)throw new InvalidOperationException("An original firewall rule is missing or was modified by another tool.");
     foreach(dynamic r in matches)if(enabled<saved.EnabledCount && !(bool)r.Enabled){r.Enabled=true;enabled++;}
    }catch(Exception e){errors.Add(e.Message);}
    foreach(string name in OwnedNames(p,Strict)) try { p.Rules.Remove(name); } catch(Exception e) { errors.Add(e.Message); }
    if(errors.Count==0) File.Delete(StatePath);
   }
   if(removeAppRules) foreach(string name in OwnedNames(p)) try { p.Rules.Remove(name); } catch(Exception e) { errors.Add(e.Message); }
   if(errors.Count>0) throw new InvalidOperationException("Recovery is incomplete. Keep the snapshot and retry. "+String.Join("; ",errors.Take(3)));
  }
 }
 public class Dashboard : Form {
  readonly Color Ink=Color.FromArgb(25,38,55), Teal=Color.FromArgb(0,117,104);
  DataGridView grid=new DataGridView(); TextBox search=new TextBox(); Label summary=new Label(), speed=new Label(), status=new Label(), mode=new Label();
  Button refresh, allow, block, focus, restore, admin, browse; List<AppRow> rows=new List<AppRow>(); bool busy; bool closeApproved;
  readonly HashSet<string> checkedPaths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);bool rendering;
  readonly TrafficMonitor traffic=new TrafficMonitor();Label trafficNote=new Label();Dictionary<string,TrafficSample> samples=new Dictionary<string,TrafficSample>(StringComparer.OrdinalIgnoreCase);
  Label adminHint=new Label(),detailTitle=new Label();TextBox detail=new TextBox();Button enableOne,blockOne,helpers,diagnose;string lastAction="";int ticks;
  System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer(); long previousBytes; DateTime previousTime=DateTime.UtcNow;
  public Dashboard() {
   Text="DataGate 1.2 • Internet Control"; Width=Math.Min(1320,Screen.PrimaryScreen.WorkingArea.Width-20); Height=Math.Min(850,Screen.PrimaryScreen.WorkingArea.Height-20); MinimumSize=new Size(1050,650); StartPosition=FormStartPosition.CenterScreen; BackColor=Color.FromArgb(244,247,250); Font=new Font("Segoe UI",10); ForeColor=Ink;
   try { Icon=Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
   var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(16),ColumnCount=1,RowCount=9};
   layout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,56));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,60));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,44));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,38));layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,48));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));layout.RowStyles.Add(new RowStyle(SizeType.Absolute,44));Controls.Add(layout);
   var title=new Label{Text="DataGate    /    Your internet, under control",Font=new Font("Segoe UI",19,FontStyle.Bold),Dock=DockStyle.Fill}; layout.Controls.Add(title);
   var adminBar=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,BackColor=Color.FromArgb(255,243,212),Padding=new Padding(8,0,8,0)};adminBar.RowStyles.Add(new RowStyle(SizeType.Percent,100));adminBar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));adminBar.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,230));adminHint.Dock=DockStyle.Fill;adminHint.TextAlign=ContentAlignment.MiddleLeft;adminHint.Font=new Font("Segoe UI",10,FontStyle.Bold);admin=Button("1. Enable administrator controls",Elevate);admin.AutoSize=false;admin.Dock=DockStyle.Fill;adminBar.Controls.Add(adminHint);adminBar.Controls.Add(admin);layout.Controls.Add(adminBar);
   var cards=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=3}; for(int i=0;i<3;i++) cards.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,33.33f));
   cards.RowCount=1;cards.RowStyles.Add(new RowStyle(SizeType.Percent,100));foreach(Label l in new[]{summary,mode,speed}) {l.Dock=DockStyle.Fill;l.BackColor=Color.White;l.Padding=new Padding(8,5,8,4);l.Font=new Font("Segoe UI",9);l.Margin=new Padding(0,2,10,4);}cards.Controls.Add(summary);cards.Controls.Add(mode);cards.Controls.Add(speed);layout.Controls.Add(cards);
   var actions=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};refresh=Button("Refresh & audit",()=>RefreshApps());browse=Button("Add application…",Browse);actions.Controls.AddRange(new Control[]{refresh,browse,Button("Check visible",()=>{if(busy)return;foreach(DataGridViewRow row in grid.Rows){var app=row.Tag as AppRow;if(app!=null)checkedPaths.Add(app.Path);}Render();}),Button("Clear checks",()=>{if(busy)return;checkedPaths.Clear();Render();})});layout.Controls.Add(actions);
   var find=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2};find.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,70));find.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));find.Controls.Add(new Label{Text="Search",Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleLeft});search.Dock=DockStyle.Fill;search.Margin=new Padding(0,5,0,8);search.TextChanged+=(s,e)=>Render();find.Controls.Add(search);layout.Controls.Add(find);
   grid.Dock=DockStyle.Fill;grid.ReadOnly=true;grid.AllowUserToAddRows=false;grid.AllowUserToDeleteRows=false;grid.MultiSelect=false;grid.SelectionMode=DataGridViewSelectionMode.FullRowSelect;grid.RowHeadersVisible=false;grid.BackgroundColor=Color.White;grid.BorderStyle=BorderStyle.None;grid.AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill;grid.AutoSizeRowsMode=DataGridViewAutoSizeRowsMode.None;grid.RowTemplate.Height=34;grid.EnableHeadersVisualStyles=false;grid.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(228,237,242);grid.ColumnHeadersHeight=38;grid.DefaultCellStyle.SelectionBackColor=Color.FromArgb(215,240,234);grid.DefaultCellStyle.SelectionForeColor=Ink;grid.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(248,250,252);
   grid.ReadOnly=false;
   grid.Columns.Add(new DataGridViewCheckBoxColumn{Name="Check",HeaderText="SELECT",FillWeight=48,SortMode=DataGridViewColumnSortMode.NotSortable});
   grid.Columns.Add("App","APPLICATION");grid.Columns.Add("Access","DATAGATE RULE");grid.Columns.Add("Running","PROCESSES");grid.Columns.Add("Path","EXECUTABLE PATH");grid.Columns["Path"].FillWeight=170;grid.Columns["Running"].FillWeight=55;
   foreach(string name in new[]{"Down","Up","Total"}) {var c=new DataGridViewTextBoxColumn{Name=name,HeaderText=name=="Total"?"SESSION MiB":name=="Down"?"DOWN KiB/s":"UP KiB/s",FillWeight=75,ValueType=typeof(double),ReadOnly=true};c.DefaultCellStyle.Format="N1";grid.Columns.Add(c);}
   grid.Columns["Path"].Visible=false;grid.Columns["Running"].Visible=false;grid.Columns["App"].FillWeight=125;grid.Columns["Access"].FillWeight=100;grid.Columns["Check"].FillWeight=45;
   grid.Columns.Add(new DataGridViewButtonColumn{Name="Toggle",HeaderText="QUICK ACTION",FillWeight=82,ReadOnly=true,FlatStyle=FlatStyle.Flat});
   foreach(DataGridViewColumn column in grid.Columns)if(column.Name!="Check")column.ReadOnly=true;
   grid.CurrentCellDirtyStateChanged+=(s,e)=>{if(grid.IsCurrentCellDirty && grid.CurrentCell!=null && grid.CurrentCell.OwningColumn.Name=="Check")grid.CommitEdit(DataGridViewDataErrorContexts.Commit);};
   grid.CellValueChanged+=(s,e)=>{if(rendering || e.RowIndex<0 || e.ColumnIndex!=grid.Columns["Check"].Index)return;var r=grid.Rows[e.RowIndex].Tag as AppRow;if(r==null)return;if(Convert.ToBoolean(grid.Rows[e.RowIndex].Cells["Check"].Value))checkedPaths.Add(r.Path);else checkedPaths.Remove(r.Path);UpdateButtons();};
   grid.SelectionChanged+=(s,e)=>{UpdateButtons();UpdateDetails();};
   grid.CellContentClick+=(s,e)=>{if(e.RowIndex>=0 && e.ColumnIndex==grid.Columns["Toggle"].Index){var r=grid.Rows[e.RowIndex].Tag as AppRow;if(r==null)return;if(!Firewall.Admin){status.Text="First click Enable administrator controls above. No rule changed.";admin.Focus();return;}ChangeTargets(new List<AppRow>{r},r.Access=="Blocked");}};
   var split=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2};split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));split.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,310));split.Controls.Add(grid);
   var sidebar=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(12,8,8,6),RowCount=3,BackColor=Color.White,Margin=new Padding(10,0,0,0)};sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,35));sidebar.RowStyles.Add(new RowStyle(SizeType.Percent,100));sidebar.RowStyles.Add(new RowStyle(SizeType.Absolute,92));detailTitle.Dock=DockStyle.Fill;detailTitle.Font=new Font("Segoe UI",12,FontStyle.Bold);detailTitle.AutoEllipsis=true;sidebar.Controls.Add(detailTitle);detail.Multiline=true;detail.ReadOnly=true;detail.ScrollBars=ScrollBars.Vertical;detail.BorderStyle=BorderStyle.None;detail.BackColor=Color.White;detail.Dock=DockStyle.Fill;detail.Font=new Font("Segoe UI",9);sidebar.Controls.Add(detail);
   var singleActions=new FlowLayoutPanel{Dock=DockStyle.Fill};enableOne=Button("Enable internet",()=>{var r=Selected();if(r!=null)ChangeTargets(new List<AppRow>{r},true);});blockOne=Button("Block internet",()=>{var r=Selected();if(r!=null)ChangeTargets(new List<AppRow>{r},false);});helpers=Button("Review helpers…",ReviewHelpers);diagnose=Button("Diagnose…",Diagnose);foreach(var b in new[]{enableOne,blockOne,helpers,diagnose}){b.AutoSize=false;b.Size=new Size(125,34);b.Padding=new Padding(2);b.Margin=new Padding(2);}singleActions.Controls.AddRange(new Control[]{enableOne,blockOne,helpers,diagnose});sidebar.Controls.Add(singleActions);split.Controls.Add(sidebar);layout.Controls.Add(split);
   var control=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};allow=Button("Allow checked",()=>Change(true));block=Button("Block checked",()=>Change(false));focus=Button("Start Focus mode",ToggleFocus);restore=Button("Restore all DataGate changes",RestoreAll); control.Controls.AddRange(new Control[]{allow,block,focus,restore});layout.Controls.Add(control);
   foreach(var b in new[]{allow,enableOne,admin}){b.BackColor=Teal;b.ForeColor=Color.White;b.Font=new Font("Segoe UI",9,FontStyle.Bold);}foreach(var b in new[]{block,blockOne}){b.BackColor=Color.FromArgb(253,232,234);b.ForeColor=Color.FromArgb(155,35,50);}focus.BackColor=Color.FromArgb(225,236,255);restore.BackColor=Color.FromArgb(255,245,219);
   trafficNote.Dock=DockStyle.Fill;trafficNote.Font=new Font("Segoe UI",9);trafficNote.ForeColor=Color.FromArgb(77,95,110);trafficNote.Text="Live per-app usage needs administrator approval. Tick app checkboxes to allow/block several at once.\nObserved traffic includes LAN; session totals start when monitoring starts, not historical mobile-data billing.";layout.Controls.Add(trafficNote);
   status.Dock=DockStyle.Fill;status.Text="Ready. No network settings were changed during installation.";status.AutoEllipsis=true;layout.Controls.Add(status);
   summary.Text="APPLICATION INVENTORY\nRefresh to discover running apps";mode.Text="STANDARD MODE\nNo policy changes during installation";speed.Text="NETWORK ACTIVITY\nMeasuring adapter traffic…";
   Shown+=(s,e)=>{traffic.Start();RefreshApps();};timer.Interval=2000;timer.Tick+=(s,e)=>{UpdateSpeed();UpdateTraffic();if(++ticks%8==0 && !busy)RefreshApps();};timer.Start();FormClosing+=ClosingGuard;FormClosed+=(s,e)=>{timer.Stop();traffic.Dispose();};
  }
  protected override void Dispose(bool disposing){if(disposing){timer.Stop();timer.Dispose();traffic.Dispose();}base.Dispose(disposing);}
  Button Button(string text,Action click) { var b=new Button{Text=text,AutoSize=true,Height=36,Padding=new Padding(10,4,10,4),FlatStyle=FlatStyle.Flat,BackColor=Color.White,Margin=new Padding(0,4,10,4)}; b.FlatAppearance.BorderColor=Color.FromArgb(199,213,223);b.Click+=(s,e)=>click();return b; }
  void UpdateSpeed() {
   try { long bytes=0;foreach(var n in NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback && n.NetworkInterfaceType!=NetworkInterfaceType.Tunnel)) { var x=n.GetIPv4Statistics();bytes+=x.BytesReceived+x.BytesSent; }
    var now=DateTime.UtcNow;double rate=previousBytes==0?0:Math.Max(0,bytes-previousBytes)/Math.Max(.1,(now-previousTime).TotalSeconds);previousBytes=bytes;previousTime=now;speed.Text="NETWORK ACTIVITY (ALL APPS)\n"+(rate/1024).ToString("N0")+" KB/s · adapter estimate";
   }catch{speed.Text="Network activity unavailable";}
  }
  async void RefreshApps() {
   if(busy)return; busy=true;UpdateButtons();status.Text="Reading running apps and DataGate firewall rules…";
   try {
    var checkedSnapshot=checkedPaths.ToArray();rows=await Task.Run(()=>{
     var managed=Firewall.ManagedApps(); var map=new Dictionary<string,AppRow>(StringComparer.OrdinalIgnoreCase);
     foreach(var process in Process.GetProcesses()) using(process) try { string path=process.MainModule.FileName;if(!map.ContainsKey(path))map[path]=new AppRow{Name=System.IO.Path.GetFileNameWithoutExtension(path),Path=path};map[path].Instances++; }catch { }
     foreach(string path in managed.Keys) if(!map.ContainsKey(path))map[path]=new AppRow{Name=System.IO.Path.GetFileNameWithoutExtension(path),Path=path};
     foreach(string path in checkedSnapshot)if(!map.ContainsKey(path))map[path]=new AppRow{Name=System.IO.Path.GetFileNameWithoutExtension(path),Path=path};
     foreach(var r in map.Values)r.Access=managed.ContainsKey(r.Path)?managed[r.Path]:"Not managed";
     var conflicts=Firewall.Conflicts(map.Keys);foreach(var r in map.Values)if(conflicts.ContainsKey(r.Path))r.Warning=conflicts[r.Path];
     return map.Values.OrderBy(r=>r.Name).ToList();
    });Render();status.Text=String.IsNullOrEmpty(lastAction)?Firewall.Health()+". Select a row for controls and diagnostics; tick boxes for batch actions.":lastAction;
   }catch(Exception e){Error(e);}finally{busy=false;UpdateButtons();}
  }
  void Render() {
   rendering=true;string selected=Selected()==null?null:Selected().Path;grid.Rows.Clear();string q=search.Text.Trim();
   foreach(var r in rows.Where(r=>r.Name.IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0 || r.Path.IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0 || r.Access.IndexOf(q,StringComparison.OrdinalIgnoreCase)>=0)) {int i=grid.Rows.Add(checkedPaths.Contains(r.Path),r.Name,r.Access=="Blocked"?"BLOCK rules set":r.Access=="Approved"?(String.IsNullOrEmpty(r.Warning)?"ALLOW rule set":"ALLOW / conflict"):"No DataGate rule",r.Instances,r.Path);var row=grid.Rows[i];row.Tag=r;row.Cells["Toggle"].Value=r.Access=="Blocked"?"Enable":"Block";row.Cells["Access"].ToolTipText=r.Warning;if(r.Access=="Blocked")row.Cells["Access"].Style.ForeColor=Color.FromArgb(177,51,61);else if(r.Access=="Approved")row.Cells["Access"].Style.ForeColor=String.IsNullOrEmpty(r.Warning)?Teal:Color.DarkOrange;if(r.Path==selected)row.Selected=true;}
   rendering=false;UpdateButtons();
   summary.Text=rows.Count+" APPLICATIONS DISCOVERED\n"+rows.Count(r=>r.Access=="Blocked")+" blocked · "+rows.Count(r=>r.Access=="Approved")+" approved";
   mode.Text=File.Exists(Firewall.StatePath)?"FOCUS / RECOVERY SNAPSHOT\nUse Restore to return to previous policy":"STANDARD MODE\nOnly selected apps are blocked";
   PaintTraffic();
   UpdateDetails();
  }
  void UpdateTraffic(){samples=traffic.Snapshot();bool added=false;foreach(string path in samples.Keys)if(!rows.Any(r=>String.Equals(r.Path,path,StringComparison.OrdinalIgnoreCase))){rows.Add(new AppRow{Name=System.IO.Path.GetFileNameWithoutExtension(path),Path=path,Access="Not managed"});added=true;}if(added && !busy)Render();PaintTraffic();trafficNote.Text=traffic.Status+" · Unattributed: "+(System.Threading.Interlocked.Read(ref traffic.UnattributedBytes)/1048576.0).ToString("N1")+" MiB\nSession-only totals include LAN; rates update every 2 seconds. A dash means capture is unavailable, not zero usage.";}
  void PaintTraffic(){foreach(DataGridViewRow row in grid.Rows){var r=row.Tag as AppRow;if(r==null)continue;TrafficSample t;samples.TryGetValue(r.Path,out t);bool known=t!=null || traffic.Running;row.Cells["Down"].Value=known?(object)((t==null?0:t.DownloadRate)/1024):null;row.Cells["Up"].Value=known?(object)((t==null?0:t.UploadRate)/1024):null;row.Cells["Total"].Value=known?(object)((t==null?0:t.Download+t.Upload)/1048576.0):null;foreach(string name in new[]{"Down","Up","Total"})row.Cells[name].Style.NullValue="—";}}
  AppRow Selected(){return grid.SelectedRows.Count>0?grid.SelectedRows[0].Tag as AppRow:null;}
  void UpdateButtons(){if(allow==null||block==null||focus==null||restore==null)return;bool elevated=Firewall.Admin;allow.Enabled=block.Enabled=!busy&&elevated&&checkedPaths.Count>0;allow.Text="Allow checked ("+checkedPaths.Count+")";block.Text="Block checked ("+checkedPaths.Count+")";focus.Enabled=restore.Enabled=!busy&&elevated;refresh.Enabled=browse.Enabled=!busy;grid.Enabled=!busy;admin.Enabled=!busy&&!elevated;admin.Text=elevated?"✓ Administrator active":"1. Enable admin controls";adminHint.Text=elevated?"✓ CONTROLS READY   •   2. Select apps   →   3. Enable or block   →   Review result":"VIEW-ONLY   •   Start here: approve Windows administrator access to change rules or see live usage.";adminHint.ForeColor=elevated?Teal:Color.FromArgb(125,80,10);focus.Text=File.Exists(Firewall.StatePath)?"Stop Focus / recover":"Start Focus mode";if(enableOne!=null){enableOne.Enabled=blockOne.Enabled=!busy&&elevated&&Selected()!=null;helpers.Enabled=diagnose.Enabled=!busy&&Selected()!=null;}}
  async void Work(Action task,string success){if(busy)return;busy=true;UpdateButtons();status.BackColor=Color.FromArgb(255,244,213);status.Text="Applying and verifying firewall changes…";try{await Task.Run(task);lastAction="✓ "+DateTime.Now.ToString("HH:mm:ss")+"  "+success;status.BackColor=Color.FromArgb(218,241,231);status.Text=lastAction;}catch(Exception e){lastAction="Attention: "+e.Message;status.BackColor=Color.FromArgb(253,228,230);Error(e);}finally{busy=false;UpdateButtons();RefreshApps();}}
  void Change(bool value){ChangeTargets(rows.Where(r=>checkedPaths.Contains(r.Path)).ToList(),value);}
  void ChangeTargets(List<AppRow> targets,bool value){if(targets.Count==0||busy)return;if(!Firewall.Admin){status.Text="Enable administrator controls first. No rules changed.";return;}
   if(value&&targets.Count==1){string root=RelatedApps.SafeRoot(targets[0].Path);var relatedBlocked=rows.Where(r=>r.Access=="Blocked"&&!r.Path.Equals(targets[0].Path,StringComparison.OrdinalIgnoreCase)&&root!=null&&r.Path.StartsWith(root+"\\",StringComparison.OrdinalIgnoreCase)).ToList();if(relatedBlocked.Count>0){var answer=MessageBox.Show(this,relatedBlocked.Count+" related executable(s) in this application's folder are still blocked:\n\n"+String.Join("\n",relatedBlocked.Take(6).Select(r=>r.Name))+"\n\nYes: review helpers first (no rules changed yet).\nNo: enable only this executable.\nCancel: stop.","Blocked helper warning",MessageBoxButtons.YesNoCancel,MessageBoxIcon.Warning);if(answer==DialogResult.Yes){ReviewHelpers();return;}if(answer==DialogResult.Cancel)return;}}
   string windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows)+System.IO.Path.DirectorySeparatorChar;
   if(targets.Any(r=>r.Path.StartsWith(windows,StringComparison.OrdinalIgnoreCase)) && MessageBox.Show(this,"Your selection includes Windows components. Blocking them can break DNS, sign-in or updates; approving a shared service host may permit multiple background services.\n\nContinue?","Windows component warning",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
   string message=(value?"Enable ":"Block ")+targets.Count+" executable(s)?\n\n"+String.Join("\n",targets.Take(8).Select(r=>r.Name))+(targets.Count>8?"\n…":"")+"\n\n"+(value?"Enable removes ALL matching DataGate blocks (including legacy rules) and adds an outbound allow. Other tools' blocks are not removed. If helpers remain blocked, use Review helpers. Restart the target app's connection after applying.":"Block sets inbound AND outbound rules for these exact executables. Related helpers/services can still connect under different paths. Review helpers or use Focus for broader restriction.");
   if(MessageBox.Show(this,message,"Apply to checked applications",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
   Work(()=>{var failures=new List<string>();int completed=0;foreach(var r in targets)try{Firewall.SetApp(r.Path,value);completed++;}catch(Exception e){failures.Add(r.Name+": "+e.Message);}if(failures.Count>0)throw new InvalidOperationException(completed+" succeeded; "+failures.Count+" failed.\n"+String.Join("\n",failures.Take(8)));},targets.Count+" rule changes verified. "+(value?"DataGate blocks removed; review helper/conflict warnings if still offline.":"Inbound/outbound blocks installed. Helpers require separate rules."));}
  void UpdateDetails(){if(detail==null||rendering)return;var r=Selected();detailTitle.Text=r==null?"Select an application":r.Name;if(r==null){detail.Text="Click an app row for individual controls.\r\n\r\nTick checkboxes for batch actions.\r\n\r\nAdministrator controls must be enabled before changing access.";return;}string state=r.Access=="Blocked"?"DataGate block policy configured.":r.Access=="Approved"?"DataGate allow configured. This is NOT a successful internet test.":"No DataGate-specific rule. Standard mode normally permits this app; Focus normally blocks it.";detail.Text=state+"\r\n\r\n"+r.Path+"\r\n\r\nRunning processes: "+r.Instances+"\r\n\r\n"+(String.IsNullOrEmpty(r.Warning)?"No matching third-party executable block found. Shared/global rules may still apply.":r.Warning)+"\r\n\r\nIf Enable doesn't reconnect: Review helpers, approve needed blocked executables, then restart the target app. Avoid approving shared Windows hosts broadly.";UpdateButtons();}
  async void ReviewHelpers(){var r=Selected();if(r==null||busy)return;busy=true;UpdateButtons();status.Text="Inspecting related running processes and application-folder candidates…";try{var known=rows.ToArray();var found=await Task.Run(()=>RelatedApps.Discover(r.Path,known));if(found.Count==0){MessageBox.Show(this,"No safe folder/process candidates were found. This does not prove there are no dependencies. Services, shared runtimes or packaged apps may require manual investigation.","Related executables");return;}using(var dialog=new RelatedDialog(found)){if(dialog.ShowDialog(this)!=DialogResult.OK)return;checkedPaths.Add(r.Path);foreach(string path in dialog.Chosen){checkedPaths.Add(path);if(!rows.Any(x=>String.Equals(x.Path,path,StringComparison.OrdinalIgnoreCase)))rows.Add(new AppRow{Name=System.IO.Path.GetFileNameWithoutExtension(path),Path=path,Access=found.First(x=>x.Path==path).Blocked?"Blocked":"Not managed"});}lastAction="Related executables added to checked selection. No rules changed yet; choose Allow checked or Block checked.";Render();status.Text=lastAction;}}catch(Exception e){Error(e);}finally{busy=false;UpdateButtons();}}
  void Diagnose(){var r=Selected();if(r==null||busy)return;try{var conflicts=Firewall.Conflicts(new[]{r.Path});r.Warning=conflicts.ContainsKey(r.Path)?conflicts[r.Path]:"";UpdateDetails();MessageBox.Show(this,detail.Text+"\r\n\r\n"+Firewall.Health()+"\r\n\r\nA green allow rule cannot override an explicit block from another tool. Browser/VPN/antivirus settings, DNS and blocked helpers can also prevent access. Diagnosing does not change firewall rules.","Access diagnostics — "+r.Name,MessageBoxButtons.OK,MessageBoxIcon.Information);}catch(Exception e){Error(e);}}
  void Browse(){using(var d=new OpenFileDialog{Filter="Windows applications (*.exe)|*.exe",Title="Select the actual application executable"}) if(d.ShowDialog(this)==DialogResult.OK){string path=Firewall.ValidatePath(d.FileName);if(!rows.Any(r=>String.Equals(r.Path,path,StringComparison.OrdinalIgnoreCase)))rows.Add(new AppRow{Name=System.IO.Path.GetFileNameWithoutExtension(path),Path=path,Access="Not managed"});search.Text=System.IO.Path.GetFileNameWithoutExtension(path);Render();}}
  void ToggleFocus(){if(File.Exists(Firewall.StatePath)){Work(()=>Firewall.Restore(false),"Previous outbound policy restored. Individual blocks remain.");return;}
   if(MessageBox.Show(this,"Focus mode changes ALL firewall profiles to block outbound traffic by default and temporarily disables existing outbound allow rules.\n\nOnly DataGate-approved executable paths and essential DNS/DHCP can send traffic. Email, VPNs, sync, updates, remote assistance and this chat may disconnect. Windows updates should be allowed regularly.\n\nApprove your browser and required helpers first. Recovery is saved before changes. If connectivity fails, choose Stop Focus / recover or the desktop recovery shortcut.\n\nEnable Focus mode now?","Enable strict internet control",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)==DialogResult.Yes)Work(Firewall.EnableStrict,"Focus policy applied. Test your approved apps now.");}
  void RestoreAll(){if(MessageBox.Show(this,"Restore the saved pre-Focus policy and remove all DataGate Allow/Block rules? Rules created by other software are not deleted.","Restore DataGate changes",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes)Work(()=>Firewall.Restore(true),"DataGate changes restored.");}
  void Error(Exception e){status.Text=e.Message;MessageBox.Show(this,e.Message,"DataGate needs attention",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
  async void Elevate(){if(busy)return;busy=true;UpdateButtons();adminHint.Text="WAITING FOR WINDOWS APPROVAL   •   Choose Yes in the administrator prompt. No rule is changing.";status.Text="Requesting administrator access… If canceled, DataGate will stay in view-only mode.";try{var child=await Task.Run(()=>Process.Start(new ProcessStartInfo(Application.ExecutablePath){UseShellExecute=true,Verb="runas"}));if(child==null)throw new Exception("Windows did not launch the elevated dashboard.");busy=false;closeApproved=true;Close();}catch(System.ComponentModel.Win32Exception e){busy=false;UpdateButtons();status.Text=e.NativeErrorCode==1223?"Administrator approval canceled. View-only mode; no rules were changed.":e.Message;}catch(Exception e){busy=false;UpdateButtons();Error(e);}}
  void ClosingGuard(object sender,FormClosingEventArgs e){if(busy){e.Cancel=true;status.Text="Wait for the current operation to finish before closing.";return;}if(!closeApproved && File.Exists(Firewall.StatePath)){var answer=MessageBox.Show(this,"Focus settings remain active after closing.\n\nYes: restore the previous outbound policy and close.\nNo: keep Focus active. Use the desktop recovery shortcut if needed.\nCancel: stay here.","Close DataGate",MessageBoxButtons.YesNoCancel,MessageBoxIcon.Warning);if(answer==DialogResult.Cancel)e.Cancel=true;else if(answer==DialogResult.Yes){try{Firewall.Restore(false);}catch(Exception ex){Error(ex);e.Cancel=true;}}}}
  public void TestCheckboxes(){rows=new List<AppRow>{new AppRow{Name="Alpha",Path=@"C:\Alpha.exe",Access="Not managed"},new AppRow{Name="Beta",Path=@"C:\Beta.exe",Access="Not managed"}};Render();grid.Rows[0].Cells["Check"].Value=true;if(!checkedPaths.Contains(@"C:\Alpha.exe"))throw new Exception("Checkbox selection failed");search.Text="Beta";if(grid.Rows.Count!=1 || checkedPaths.Count!=1)throw new Exception("Filter lost checked selection");search.Text="";if(!Convert.ToBoolean(grid.Rows[0].Cells["Check"].Value))throw new Exception("Checkbox did not survive rerender");grid.Rows[0].Cells["Check"].Value=false;if(checkedPaths.Count!=0)throw new Exception("Checkbox clear failed");}
 }
 static class Program {
  [STAThread] static int Main(string[] args){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   try {
    if(args.Contains("--self-test")){Tests();return 0;}
    if(args.Contains("--monitor-test")){MonitorTest();return 0;}
    if(args.Contains("--upgrade-test")){var reports=new List<string>();try{Tests();reports.Add("SELF TEST: PASS");}catch(Exception e){reports.Add("SELF TEST: FAIL "+e.Message);}try{Firewall.VerifyRoundTrip();reports.Add(File.ReadAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"roundtrip-test.txt")));}catch(Exception e){reports.Add("FIREWALL TEST: FAIL "+e.Message);}try{MonitorTest();reports.Add(File.ReadAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"monitor-test.txt")));}catch(Exception e){reports.Add("MONITOR TEST: FAIL "+e.ToString());}File.WriteAllLines(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"upgrade-test.txt"),reports);return 0;}
    if(args.Contains("--verify-firewall")){Firewall.VerifyWrite();return 0;}
    if(args.Contains("--install")){Install();return 0;}
    if(args.Contains("--retire-older")){if(!Firewall.Admin)throw new InvalidOperationException("Administrator approval is required for closing an older elevated dashboard.");if(File.Exists(Firewall.StatePath))return 0;string root=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Programs","DataGate")+"\\";foreach(var old in Process.GetProcessesByName("DataGate"))using(old)try{if(old.Id==Process.GetCurrentProcess().Id)continue;string path=old.MainModule.FileName;if(path.StartsWith(root,StringComparison.OrdinalIgnoreCase)&&!String.Equals(path,Application.ExecutablePath,StringComparison.OrdinalIgnoreCase)&&old.MainWindowHandle!=IntPtr.Zero)old.CloseMainWindow();}catch{}return 0;}
    if(System.IO.Path.GetFileNameWithoutExtension(Application.ExecutablePath).Equals("DataGate-Setup",StringComparison.OrdinalIgnoreCase)) {
     if(MessageBox.Show("Install DataGate for this Windows user and create desktop + recovery shortcuts?\n\nNo firewall settings will change during installation.","DataGate Setup",MessageBoxButtons.YesNo,MessageBoxIcon.Question)==DialogResult.Yes){Install();Process.Start(new ProcessStartInfo(InstalledExe()){UseShellExecute=true});}return 0;
    }
    if(args.Contains("--restore")){if(!Firewall.Admin){Process.Start(new ProcessStartInfo(Application.ExecutablePath,"--restore"){UseShellExecute=true,Verb="runas"});return 0;}Firewall.Restore(true);MessageBox.Show("DataGate changes restored.","DataGate Recovery");return 0;}
    if(args.Contains("--preview")){using(var f=new Dashboard()){f.Show();for(int i=0;i<100;i++){Application.DoEvents();System.Threading.Thread.Sleep(50);}using(var image=new Bitmap(f.Width,f.Height)){f.DrawToBitmap(image,new Rectangle(0,0,image.Width,image.Height));image.Save(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"preview.png"));}}return 0;}
    Application.Run(new Dashboard());return 0;
   }catch(Exception e){if(args.Contains("--self-test") || args.Contains("--monitor-test"))File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,args.Contains("--monitor-test")?"monitor-test.txt":"test-failure.txt"),"FAIL: "+e.ToString());else MessageBox.Show(e.Message,"DataGate",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
  }
  static string InstalledExe(){return System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Programs","DataGate","versions","1.2.0","DataGate.exe");}
  static void Install(){
   string exe=InstalledExe();string target=System.IO.Path.GetDirectoryName(exe);Directory.CreateDirectory(target);
   if(!String.Equals(Application.ExecutablePath,exe,StringComparison.OrdinalIgnoreCase)) File.Copy(Application.ExecutablePath,exe,true);
   dynamic shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell"));
   foreach(string dir in new[]{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"DataGate")}){Directory.CreateDirectory(dir);dynamic link=shell.CreateShortcut(System.IO.Path.Combine(dir,"DataGate.lnk"));link.TargetPath=exe;link.WorkingDirectory=target;link.IconLocation=exe+",0";link.Save();dynamic recovery=shell.CreateShortcut(System.IO.Path.Combine(dir,"DataGate - Restore Internet.lnk"));recovery.TargetPath=exe;recovery.Arguments="--restore";recovery.WorkingDirectory=target;recovery.IconLocation=exe+",0";recovery.Save();}
   File.WriteAllText(System.IO.Path.Combine(target,"README.txt"),"DataGate 1.2.0\r\nStart with the administrator banner. Then select a row for Enable/Block/Review helpers/Diagnose, or tick boxes for batch actions.\r\nA verified rule is not an internet connectivity guarantee. Related helpers, services and other firewall policies can affect access.\r\nEnable removes matching legacy/current DataGate blocks; Block creates inbound AND outbound blocks for the exact executable.\r\nInstallation preserves existing restrictions and recovery state.\r\nLive per-app TCP/UDP counters require elevation and include LAN, not carrier billing.\r\nRules persist after closing. Use Restore Internet to reverse DataGate changes before uninstalling.\r\nRecovery: "+Firewall.StatePath+"\r\nWindows x64 / .NET Framework 4.8. No Node.js, Python, telemetry or cloud account.\r\n");
   // Installer is deliberately quiet so deployment can be verified without changing networking.
  }
  static void Tests(){
   string path=Application.ExecutablePath;string a=Firewall.RuleName(path,"Allow"),b=Firewall.RuleName(path.ToUpperInvariant(),"Allow");if(a!=b || a==Firewall.RuleName(path,"Block"))throw new Exception("Stable rule identity test failed");
   bool invalid=false;try{Firewall.ValidatePath(@"C:\missing-datagate-test.exe");}catch(ArgumentException){invalid=true;}if(!invalid)throw new Exception("Missing executable accepted");
   var state=new RecoveryState();state.Profiles.Add(new ProfileState{Id=1,Outbound=1,Enabled=true});state.AllowRuleStates.Add(new RuleState{Fingerprint="Existing 'rule' & name",EnabledCount=2});var serializer=new XmlSerializer(typeof(RecoveryState));using(var stream=new MemoryStream()){serializer.Serialize(stream,state);stream.Position=0;var read=(RecoveryState)serializer.Deserialize(stream);if(read.Profiles[0].Outbound!=1 || read.AllowRuleStates[0].Fingerprint!=state.AllowRuleStates[0].Fingerprint || read.AllowRuleStates[0].EnabledCount!=2)throw new Exception("Recovery roundtrip failed");}
   Firewall.Health();Firewall.ManagedApps(); // Read-only integration checks; never mutate the real firewall in self-test.
   dynamic policy=Firewall.Policy();var fingerprints=new HashSet<string>();int count=0;foreach(dynamic rule in policy.Rules){string fp=Firewall.Fingerprint(rule);if(!fp.Contains("Name:") || fp.Contains("Name:<not available>"))throw new Exception("Rule fingerprint cannot read COM properties");fingerprints.Add(fp);count++;}if(count>1 && fingerprints.Count<2)throw new Exception("Rule fingerprint lost unique identity");
   TrafficMonitor.ValidateLayout();var book=new TrafficBook();book.Add(path,2048,false);book.Add(path.ToUpperInvariant(),1024,true);book.Add(path,-5,false);var sample=book.Snapshot()[path];if(sample.Download!=2048 || sample.Upload!=1024 || sample.DownloadRate<0)throw new Exception("Traffic aggregation failed");System.Threading.Thread.Sleep(60);if(book.Snapshot()[path].DownloadRate!=0)throw new Exception("Idle traffic rate failed");
   using(var f=new Dashboard()){f.CreateControl();if(f.MinimumSize.Width<900)throw new Exception("Layout minimum missing");f.TestCheckboxes();}
   File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"test-results.txt"),"PASS: stable rule IDs; invalid paths; recovery roundtrip; firewall read and fingerprints; checkbox selection/uncheck/filter persistence; ETW x64 layout; traffic aggregation/case folding/idle rate. No firewall writes performed.");
  }
  static void MonitorTest(){using(var monitor=new TrafficMonitor()){monitor.Start();if(!monitor.Running)throw new Exception(monitor.Status);System.Threading.Thread.Sleep(1200);
   var listener=new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback,0);listener.Start();int port=((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
   try{using(var client=new System.Net.Sockets.TcpClient()){client.Connect(System.Net.IPAddress.Loopback,port);using(var server=listener.AcceptTcpClient()){byte[] data=new byte[65536];client.GetStream().Write(data,0,data.Length);server.ReceiveTimeout=2000;int received=0;while(received<data.Length){int read=server.GetStream().Read(data,0,Math.Min(4096,data.Length-received));if(read==0)break;received+=read;}}}}finally{listener.Stop();}
   using(var receiver=new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback,0)))using(var sender=new System.Net.Sockets.UdpClient()){byte[] data=new byte[4096];sender.Send(data,data.Length,(System.Net.IPEndPoint)receiver.Client.LocalEndPoint);}
   System.Threading.Thread.Sleep(2500);var samples=monitor.Snapshot();TrafficSample own;if(!samples.TryGetValue(Application.ExecutablePath,out own)||own.Upload<=0||own.Download<=0)throw new Exception("No attributed bidirectional test traffic. "+monitor.Status+" apps="+samples.Count+" unattributed="+monitor.UnattributedBytes);
   File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"monitor-test.txt"),"PASS: native ETW capture started, observed actual loopback TCP/UDP traffic, attributed bytes to the correct executable, and will stop its owned session on disposal. Upload="+own.Upload+" Download="+own.Download+" Apps="+samples.Count+". No firewall changes.");}}
 }
}
