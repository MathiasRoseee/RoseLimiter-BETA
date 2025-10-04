using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Net.NetworkInformation;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Drawing;

namespace RoseLimiter
{
    public class AppGroup : INotifyPropertyChanged
    {
        public string Name { get; set; } = "";
        public ImageSource? Icon { get; set; }
        public ObservableCollection<ProcessInfo> Children { get; set; } = new ObservableCollection<ProcessInfo>();
        
        private bool _isDownloadBlocked;
        public bool IsDownloadBlocked
        {
            get => _isDownloadBlocked;
            set
            {
                _isDownloadBlocked = value;
                OnPropertyChanged(nameof(IsDownloadBlocked));
                OnPropertyChanged(nameof(DownloadBlockIcon));
                // Tüm child'ları da engelle/aç
                foreach (var child in Children)
                    child.IsDownloadBlocked = value;
            }
        }
        
        private bool _isUploadBlocked;
        public bool IsUploadBlocked
        {
            get => _isUploadBlocked;
            set
            {
                _isUploadBlocked = value;
                OnPropertyChanged(nameof(IsUploadBlocked));
                OnPropertyChanged(nameof(UploadBlockIcon));
                // Tüm child'ları da engelle/aç
                foreach (var child in Children)
                    child.IsUploadBlocked = value;
            }
        }
        
        public string DownloadBlockIcon => IsDownloadBlocked ? "❌" : "⬇️";
        public string UploadBlockIcon => IsUploadBlocked ? "❌" : "⬆️";
        
        private string _downloadSpeed = "0 KB/s";
        public string DownloadSpeed
        {
            get => _downloadSpeed;
            set { _downloadSpeed = value; OnPropertyChanged(nameof(DownloadSpeed)); }
        }

        private string _uploadSpeed = "0 KB/s";
        public string UploadSpeed
        {
            get => _uploadSpeed;
            set { _uploadSpeed = value; OnPropertyChanged(nameof(UploadSpeed)); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            });
        }
    }

    public class ProcessInfo : INotifyPropertyChanged
    {
        public int Pid { get; set; }
        public string Name { get; set; } = "";
        
        private bool _isDownloadBlocked;
        public bool IsDownloadBlocked
        {
            get => _isDownloadBlocked;
            set
            {
                _isDownloadBlocked = value;
                OnPropertyChanged(nameof(IsDownloadBlocked));
                OnPropertyChanged(nameof(DownloadBlockIcon));
            }
        }
        
        private bool _isUploadBlocked;
        public bool IsUploadBlocked
        {
            get => _isUploadBlocked;
            set
            {
                _isUploadBlocked = value;
                OnPropertyChanged(nameof(IsUploadBlocked));
                OnPropertyChanged(nameof(UploadBlockIcon));
            }
        }
        
        public string DownloadBlockIcon => IsDownloadBlocked ? "❌" : "⬇️";
        public string UploadBlockIcon => IsUploadBlocked ? "❌" : "⬆️";

        private long _currentDownload;
        private long _currentUpload;
        private bool _hasActivity;
        public void AddDownload(long bytes) => Interlocked.Add(ref _currentDownload, bytes);
        public void AddUpload(long bytes) => Interlocked.Add(ref _currentUpload, bytes);

        public long GetAndResetDownload() 
        { 
            var val = Interlocked.Exchange(ref _currentDownload, 0);
            if (val > 0) _hasActivity = true;
            return val;
        }
        
        public long GetAndResetUpload() 
        { 
            var val = Interlocked.Exchange(ref _currentUpload, 0);
            if (val > 0) _hasActivity = true;
            return val;
        }
        
        public bool HasActivity => _hasActivity;
        public string DisplayName => $"PID: {Pid}";

        private string _downloadSpeed = "0 KB/s";
        public string DownloadSpeed
        {
            get => _downloadSpeed;
            set { _downloadSpeed = value; OnPropertyChanged(nameof(DownloadSpeed)); }
        }

        private string _uploadSpeed = "0 KB/s";
        public string UploadSpeed
        {
            get => _uploadSpeed;
            set { _uploadSpeed = value; OnPropertyChanged(nameof(UploadSpeed)); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
        {
            Application.Current?.Dispatcher.Invoke(() =>
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            });
        }
    }

    public partial class MainWindow : Window
    {
        public ObservableCollection<AppGroup> AppGroups { get; set; }
        private readonly ConcurrentDictionary<string, AppGroup> _groupDict = new ConcurrentDictionary<string, AppGroup>();
        private readonly ConcurrentDictionary<int, ProcessInfo> _pidDict = new ConcurrentDictionary<int, ProcessInfo>();
        private ICaptureDevice? _device;
        private readonly DispatcherTimer _timer;
        private static ConcurrentDictionary<ushort, int> _portToPidMap = new ConcurrentDictionary<ushort, int>();
        private IPAddress? _localIp;
        private long _totalPackets = 0;
        private long _matchedPackets = 0;
        
        // Trafik grafiği için
        private readonly Queue<double> _downloadHistory = new Queue<double>();
        private readonly Queue<double> _uploadHistory = new Queue<double>();
        private const int MaxHistoryPoints = 60; // 60 saniye

        public MainWindow()
        {
            InitializeComponent();
            AppGroups = new ObservableCollection<AppGroup>();
            AppTreeView.ItemsSource = AppGroups;
            InitializePacketCapture();

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            Task.Run(UpdatePortToPidMapLoop);

            this.Closing += MainWindow_Closing;
        }

        private void InitializePacketCapture()
        {
            try
            {
                // Yerel IP adresini NetworkInterface kullanarak al
                var activeInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up && 
                                 ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                 (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet || 
                                  ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
                    .FirstOrDefault();

                if (activeInterface == null) { MessageBox.Show("Aktif bir ağ arayüzü bulunamadı!"); return; }
                
                _localIp = activeInterface.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(ip => ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address;
                
                if (_localIp == null) { MessageBox.Show("IPv4 adresi bulunamadı!"); return; }

                var devices = CaptureDeviceList.Instance;
                if (devices.Count < 1) { MessageBox.Show("Ağ arayüzü bulunamadı! Npcap'in kurulu olduğundan emin olun."); return; }
                
                // Aktif interface'in MAC adresini al
                var macAddress = activeInterface.GetPhysicalAddress().ToString();
                
                // Bu MAC adresine sahip cihazı bul, bulamazsan ilkini al
                _device = devices.FirstOrDefault(d => d is LibPcapLiveDevice dev && 
                    dev.MacAddress?.ToString().Replace(":", "").Replace("-", "").Equals(macAddress, StringComparison.OrdinalIgnoreCase) == true) 
                    ?? devices.FirstOrDefault(d => !(d.Name?.Contains("Loopback") ?? false))
                    ?? devices[0];

                _device.OnPacketArrival += OnPacketArrival;
                _device.Open(DeviceModes.Promiscuous, 1000);
                _device.StartCapture();
                
                this.Title = $"RoseLimiter - {activeInterface.Name} ({_localIp})";
            }
            catch (Exception ex) { MessageBox.Show($"Ağ dinleme başlatılamadı: {ex.Message}\n\nNpcap kurulu değilse lütfen kurun."); }
        }

        private void OnPacketArrival(object? sender, PacketCapture e)
        {
            try
            {
                Interlocked.Increment(ref _totalPackets);
                var rawPacket = e.GetPacket();
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                var ipPacket = packet.Extract<IPPacket>();
                if (ipPacket == null) return;

                var tcpPacket = packet.Extract<TcpPacket>();
                var udpPacket = packet.Extract<UdpPacket>();

                ushort sourcePort = 0, destPort = 0;
                if (tcpPacket != null) { sourcePort = tcpPacket.SourcePort; destPort = tcpPacket.DestinationPort; }
                else if (udpPacket != null) { sourcePort = udpPacket.SourcePort; destPort = udpPacket.DestinationPort; }
                else return;

                bool isUpload = ipPacket.SourceAddress.Equals(_localIp);
                var port = isUpload ? sourcePort : destPort;

                if (_portToPidMap.TryGetValue(port, out int pid))
                {
                    Interlocked.Increment(ref _matchedPackets);
                    try
                    {
                        var process = Process.GetProcessById(pid);
                        var procName = process.ProcessName;
                        
                        // PID dict'te yoksa ekle
                        if (!_pidDict.TryGetValue(pid, out var processInfo))
                        {
                            processInfo = new ProcessInfo { Pid = pid, Name = procName };
                            _pidDict[pid] = processInfo;
                            
                            // Group'a ekle
                            if (!_groupDict.TryGetValue(procName, out var group))
                            {
                                var icon = GetProcessIcon(process);
                                group = new AppGroup { Name = procName, Icon = icon };
                                _groupDict[procName] = group;
                                Application.Current.Dispatcher.BeginInvoke(() => AppGroups.Add(group));
                            }
                            Application.Current.Dispatcher.BeginInvoke(() => group.Children.Add(processInfo));
                        }
                        
                        if (processInfo != null)
                        {
                            // Yöne göre engelleme kontrolü
                            if (isUpload && !processInfo.IsUploadBlocked)
                                processInfo.AddUpload(rawPacket.Data.Length);
                            else if (!isUpload && !processInfo.IsDownloadBlocked)
                                processInfo.AddDownload(rawPacket.Data.Length);
                        }
                    }
                    catch { /* Process might have exited */ }
                }
            }
            catch { /* Packet parsing can fail */ }
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            var total = Interlocked.Read(ref _totalPackets);
            var matched = Interlocked.Read(ref _matchedPackets);
            this.Title = $"RoseLimiter - Paketler: {total} | Eşleşen: {matched} | Port Map: {_portToPidMap.Count}";
            
            long systemTotalDown = 0;
            long systemTotalUp = 0;
            
            // Her grup için agregasyon yap
            foreach (var group in _groupDict.Values)
            {
                long totalDown = 0;
                long totalUp = 0;
                
                foreach (var child in group.Children)
                {
                    var down = child.GetAndResetDownload();
                    var up = child.GetAndResetUpload();
                    child.DownloadSpeed = FormatSpeed(down);
                    child.UploadSpeed = FormatSpeed(up);
                    totalDown += down;
                    totalUp += up;
                }
                
                group.DownloadSpeed = FormatSpeed(totalDown);
                group.UploadSpeed = FormatSpeed(totalUp);
                
                systemTotalDown += totalDown;
                systemTotalUp += totalUp;
            }
            
            // Trafik grafiği için veri ekle (KB/s cinsinden)
            _downloadHistory.Enqueue(systemTotalDown / 1024.0);
            _uploadHistory.Enqueue(systemTotalUp / 1024.0);
            
            // Maksimum nokta sayısını aşarsa eski verileri sil
            if (_downloadHistory.Count > MaxHistoryPoints)
                _downloadHistory.Dequeue();
            if (_uploadHistory.Count > MaxHistoryPoints)
                _uploadHistory.Dequeue();
            
            // Grafiği güncelle
            UpdateTrafficGraph();
        }

        private static string FormatSpeed(long bytesPerSecond)
        {
            if (bytesPerSecond < 1024)
                return $"{bytesPerSecond} B/s";
            else if (bytesPerSecond < 1024 * 1024)
                return $"{bytesPerSecond / 1024.0:F1} KB/s";
            else if (bytesPerSecond < 1024 * 1024 * 1024)
                return $"{bytesPerSecond / (1024.0 * 1024.0):F2} MB/s";
            else
                return $"{bytesPerSecond / (1024.0 * 1024.0 * 1024.0):F2} GB/s";
        }


        private static async Task UpdatePortToPidMapLoop()
        {
            while (true)
            {
                UpdatePortToPidMap();
                await Task.Delay(2000); // Update every 2 seconds
            }
        }

        private static void UpdatePortToPidMap()
        {
            var newMap = new ConcurrentDictionary<ushort, int>();
            UpdateTcpConnections(newMap);
            _portToPidMap = newMap;
        }

        private static void UpdateTcpConnections(ConcurrentDictionary<ushort, int> map)
        {
            uint bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr buffer = Marshal.AllocHGlobal((int)bufferSize);
            try
            {
                if (GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                {
                    var table = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(buffer, typeof(MIB_TCPTABLE_OWNER_PID))!;
                    IntPtr rowPtr = (IntPtr)((long)buffer + Marshal.SizeOf(table.dwNumEntries));
                    for (int i = 0; i < table.dwNumEntries; i++)
                    {
                        var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID))!;
                        map.TryAdd((ushort)IPAddress.NetworkToHostOrder((short)row.wLocalPort), (int)row.dwOwningPid);
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static ImageSource? GetProcessIcon(Process process)
        {
            try
            {
                string? iconPath = null;
                try
                {
                    iconPath = process.MainModule?.FileName;
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Sistem process'lerine erişim yok, varsayılan ikon kullan
                    return null;
                }
                
                if (string.IsNullOrEmpty(iconPath)) return null;
                if (!System.IO.File.Exists(iconPath)) return null;

                using var icon = System.Drawing.Icon.ExtractAssociatedIcon(iconPath);
                if (icon == null) return null;

                var bitmap = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(
                    icon.Handle,
                    System.Windows.Int32Rect.Empty,
                    BitmapSizeOptions.FromEmptyOptions());
                bitmap.Freeze(); // Thread-safe yap
                return bitmap;
            }
            catch { return null; }
        }

        private void BlockDownloadButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button)
            {
                if (button.Tag is AppGroup group)
                {
                    if (!group.IsDownloadBlocked)
                    {
                        var result = MessageBox.Show(
                            $"{group.Name} uygulamasının GELEN (indirme) paketlerini engellemek istiyor musunuz?\n\nEngelle: Tüm indirme trafiği Windows Firewall ile engellenir\nİptal: Hiçbir şey yapmaz",
                            "Gelen Paketleri Engelle",
                            MessageBoxButton.OKCancel,
                            MessageBoxImage.Warning);
                        
                        if (result == MessageBoxResult.OK)
                        {
                            if (AddFirewallRule(group.Name, "in"))
                            {
                                group.IsDownloadBlocked = true;
                                MessageBox.Show($"{group.Name} indirme trafiği Windows Firewall ile engellendi.", "Engellendi", MessageBoxButton.OK, MessageBoxImage.Information);
                            }
                            else
                            {
                                MessageBox.Show("Firewall kuralı eklenemedi. Uygulamayı yönetici olarak çalıştırdığınızdan emin olun.", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                        }
                    }
                    else
                    {
                        if (RemoveFirewallRule(group.Name, "in"))
                        {
                            group.IsDownloadBlocked = false;
                            MessageBox.Show($"{group.Name} indirme engeli kaldırıldı.", "Engel Kaldırıldı", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                }
                else if (button.Tag is ProcessInfo process)
                {
                    if (!process.IsDownloadBlocked)
                    {
                        var result = MessageBox.Show(
                            $"PID {process.Pid} GELEN paketlerini engellemek istiyor musunuz?",
                            "Gelen Paketleri Engelle",
                            MessageBoxButton.OKCancel,
                            MessageBoxImage.Warning);
                        
                        if (result == MessageBoxResult.OK)
                            process.IsDownloadBlocked = true;
                    }
                    else
                    {
                        process.IsDownloadBlocked = false;
                    }
                }
            }
        }

        private void BlockUploadButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button)
            {
                if (button.Tag is AppGroup group)
                {
                    if (!group.IsUploadBlocked)
                    {
                        var result = MessageBox.Show(
                            $"{group.Name} uygulamasının GİDEN (yükleme) paketlerini engellemek istiyor musunuz?\n\nEngelle: Tüm yükleme trafiği Windows Firewall ile engellenir\nİptal: Hiçbir şey yapmaz",
                            "Giden Paketleri Engelle",
                            MessageBoxButton.OKCancel,
                            MessageBoxImage.Warning);
                        
                        if (result == MessageBoxResult.OK)
                        {
                            if (AddFirewallRule(group.Name, "out"))
                            {
                                group.IsUploadBlocked = true;
                                MessageBox.Show($"{group.Name} yükleme trafiği Windows Firewall ile engellendi.", "Engellendi", MessageBoxButton.OK, MessageBoxImage.Information);
                            }
                            else
                            {
                                MessageBox.Show("Firewall kuralı eklenemedi. Uygulamayı yönetici olarak çalıştırdığınızdan emin olun.", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                        }
                    }
                    else
                    {
                        if (RemoveFirewallRule(group.Name, "out"))
                        {
                            group.IsUploadBlocked = false;
                            MessageBox.Show($"{group.Name} yükleme engeli kaldırıldı.", "Engel Kaldırıldı", MessageBoxButton.OK, MessageBoxImage.Information);
                        }
                    }
                }
                else if (button.Tag is ProcessInfo process)
                {
                    if (!process.IsUploadBlocked)
                    {
                        var result = MessageBox.Show(
                            $"PID {process.Pid} GİDEN paketlerini engellemek istiyor musunuz?",
                            "Giden Paketleri Engelle",
                            MessageBoxButton.OKCancel,
                            MessageBoxImage.Warning);
                        
                        if (result == MessageBoxResult.OK)
                            process.IsUploadBlocked = true;
                    }
                    else
                    {
                        process.IsUploadBlocked = false;
                    }
                }
            }
        }

        private bool AddFirewallRule(string processName, string direction)
        {
            try
            {
                // Process'in tam yolunu bul
                var processes = Process.GetProcessesByName(processName);
                if (processes.Length == 0) return false;
                
                string? exePath = null;
                foreach (var proc in processes)
                {
                    try
                    {
                        exePath = proc.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(exePath)) break;
                    }
                    catch { continue; }
                }
                
                if (string.IsNullOrEmpty(exePath)) return false;
                
                var ruleName = $"RoseLimiter_{processName}_{direction}";
                var dirText = direction == "in" ? "in" : "out";
                
                // netsh komutunu çalıştır
                var startInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall add rule name=\"{ruleName}\" dir={dirText} action=block program=\"{exePath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                
                using var process = Process.Start(startInfo);
                if (process == null) return false;
                
                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch { return false; }
        }

        private bool RemoveFirewallRule(string processName, string direction)
        {
            try
            {
                var ruleName = $"RoseLimiter_{processName}_{direction}";
                
                var startInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                
                using var process = Process.Start(startInfo);
                if (process == null) return false;
                
                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch { return false; }
        }

        private void UpdateTrafficGraph()
        {
            if (TrafficGraphCanvas == null) return;
            
            TrafficGraphCanvas.Children.Clear();
            
            var width = TrafficGraphCanvas.ActualWidth;
            var height = TrafficGraphCanvas.ActualHeight;
            
            if (width < 10 || height < 10) return;
            
            var downloadData = _downloadHistory.ToArray();
            var uploadData = _uploadHistory.ToArray();
            
            if (downloadData.Length < 2) return;
            
            // Etiketler için üstte ve altta boşluk bırak
            const double topMargin = 50;
            const double bottomMargin = 10;
            const double leftMargin = 5;
            const double rightMargin = 5;
            
            var graphWidth = width - leftMargin - rightMargin;
            var graphHeight = height - topMargin - bottomMargin;
            
            if (graphWidth < 10 || graphHeight < 10) return;
            
            // Maksimum değeri bul (otomatik scale için)
            var maxValue = Math.Max(downloadData.Max(), uploadData.Max());
            if (maxValue < 10) maxValue = 10; // Minimum 10 KB/s
            
            // İndirme çizgisi (Kırmızı)
            var downloadLine = new Polyline
            {
                Stroke = new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 53, 69)),
                StrokeThickness = 2,
                Points = new PointCollection()
            };
            
            for (int i = 0; i < downloadData.Length; i++)
            {
                var x = leftMargin + (i / (double)MaxHistoryPoints) * graphWidth;
                var y = topMargin + graphHeight - (downloadData[i] / maxValue * graphHeight);
                downloadLine.Points.Add(new System.Windows.Point(x, y));
            }
            
            TrafficGraphCanvas.Children.Add(downloadLine);
            
            // Yükleme çizgisi (Yeşil)
            var uploadLine = new Polyline
            {
                Stroke = new SolidColorBrush(System.Windows.Media.Color.FromRgb(40, 167, 69)),
                StrokeThickness = 2,
                Points = new PointCollection()
            };
            
            for (int i = 0; i < uploadData.Length; i++)
            {
                var x = leftMargin + (i / (double)MaxHistoryPoints) * graphWidth;
                var y = topMargin + graphHeight - (uploadData[i] / maxValue * graphHeight);
                uploadLine.Points.Add(new System.Windows.Point(x, y));
            }
            
            TrafficGraphCanvas.Children.Add(uploadLine);
            
            // Etiketler
            var downloadLabel = new TextBlock
            {
                Text = $"Gelen: {FormatSpeed((long)(downloadData.LastOrDefault() * 1024))}",
                Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(220, 53, 69)),
                FontSize = 11,
                FontWeight = FontWeights.Bold
            };
            Canvas.SetLeft(downloadLabel, 10);
            Canvas.SetTop(downloadLabel, 5);
            TrafficGraphCanvas.Children.Add(downloadLabel);
            
            var uploadLabel = new TextBlock
            {
                Text = $"Giden: {FormatSpeed((long)(uploadData.LastOrDefault() * 1024))}",
                Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(40, 167, 69)),
                FontSize = 11,
                FontWeight = FontWeights.Bold
            };
            Canvas.SetLeft(uploadLabel, 10);
            Canvas.SetTop(uploadLabel, 25);
            TrafficGraphCanvas.Children.Add(uploadLabel);
        }

        private void MainWindow_Closing(object? sender, CancelEventArgs e)
        {
            if (_device != null && _device.Started) { _device.StopCapture(); _device.Close(); }
            _timer?.Stop();
        }

        #region P/Invoke for IPHLPAPI
        private const int AF_INET = 2;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref uint pdwSize, bool bOrder, int ulAf, TCP_TABLE_CLASS TableClass, uint Reserved);

        private enum TCP_TABLE_CLASS { TCP_TABLE_OWNER_PID_ALL = 5 }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
            public MIB_TCPROW_OWNER_PID[] table;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public ushort wLocalPort;
            public uint dwRemoteAddr;
            public ushort wRemotePort;
            public uint dwOwningPid;
        }
        #endregion
    }
}