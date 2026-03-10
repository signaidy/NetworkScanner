using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace NetworkScanner
{
    class Program
    {
        private static readonly TimeSpan PortConnectTimeout = TimeSpan.FromMilliseconds(300);

        static void Main(string[] args)
        {
            Console.WriteLine("Network Scanner");

            // Record the start time
            Stopwatch stopwatch = Stopwatch.StartNew();

            // Get the router IP address and subnet mask from an active IPv4 interface
            string? routerIpAddress, subnetMask;
            GetRouterIpAndSubnet(out routerIpAddress, out subnetMask);
            if (routerIpAddress == null || subnetMask == null)
            {
                Console.WriteLine("Unable to retrieve router IP address or subnet mask. Exiting...");
                return;
            }

            Console.WriteLine($"Router IP address: {routerIpAddress}");
            Console.WriteLine($"Subnet mask: {subnetMask}");

            // Define the range of IP addresses to scan based on the subnet mask
            List<string>? ipAddresses = GetIpAddresses(routerIpAddress, subnetMask);
            if (ipAddresses == null || ipAddresses.Count == 0)
            {
                Console.WriteLine("No IP addresses to scan. Exiting...");
                return;
            }

            Console.WriteLine("Scanning network for active hosts...");

            // Perform ICMP ping sweep on the network
            List<Task> tasks = new List<Task>();

            foreach (string ipAddress in ipAddresses)
            {
                // Skip IP addresses outside the current subnet
                if (!IsIpInSameSubnet(routerIpAddress, ipAddress, subnetMask))
                {
                    continue;
                }

                if (IsHostActive(ipAddress))
                {
                    Console.WriteLine($"Host {ipAddress} is active");

                    // Start a new task for port scanning
                    Task task = Task.Run(() => CheckOpenPorts(ipAddress));
                    tasks.Add(task);
                }
            }

            // Wait for all tasks to complete
            Task.WaitAll(tasks.ToArray());

            // Stop the stopwatch and calculate the duration
            stopwatch.Stop();
            TimeSpan duration = stopwatch.Elapsed;
            Console.WriteLine($"Scan completed in {duration.TotalSeconds:F2} seconds.");

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static bool IsIpInSameSubnet(string routerIpAddress, string ipAddress, string subnetMask)
        {
            try
            {
                IPAddress routerIp = IPAddress.Parse(routerIpAddress);
                IPAddress ip = IPAddress.Parse(ipAddress);
                IPAddress mask = IPAddress.Parse(subnetMask);

                byte[] routerBytes = routerIp.GetAddressBytes();
                byte[] ipBytes = ip.GetAddressBytes();
                byte[] maskBytes = mask.GetAddressBytes();

                // Calculate network addresses for both IP addresses
                byte[] networkBytesRouter = new byte[4];
                byte[] networkBytesIP = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    networkBytesRouter[i] = (byte)(routerBytes[i] & maskBytes[i]);
                    networkBytesIP[i] = (byte)(ipBytes[i] & maskBytes[i]);
                }

                // Compare network addresses
                return networkBytesRouter.SequenceEqual(networkBytesIP);
            }
            catch
            {
                return false; // Error occurred, consider IP in different subnet
            }
        }

        static bool IsHostActive(string ipAddress)
        {
            try
            {
                using Ping ping = new Ping();
                PingReply reply = ping.Send(ipAddress, 100);

                return reply.Status == IPStatus.Success;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error pinging host {ipAddress}: {ex.Message}");
                return false;
            }
        }

        static void CheckOpenPorts(string ipAddress)
        {
            ConcurrentBag<int> openPorts = new ConcurrentBag<int>();

            Parallel.ForEach(GetCommonPorts(), port =>
            {
                try
                {
                    using (TcpClient tcpClient = new TcpClient())
                    {
                        Task connectTask = tcpClient.ConnectAsync(ipAddress, port);
                        if (connectTask.Wait(PortConnectTimeout) && tcpClient.Connected)
                        {
                            openPorts.Add(port);
                        }
                    }
                }
                catch (AggregateException ex) when (ex.InnerExceptions.All(inner => inner is SocketException))
                {
                    // Port is closed or unreachable
                }
                catch (SocketException)
                {
                    // Port is closed or unreachable
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error checking port {port} on host {ipAddress}: {ex.Message}");
                }
            });

            List<int> orderedOpenPorts = openPorts.Distinct().OrderBy(port => port).ToList();
            if (orderedOpenPorts.Any())
            {
                Console.WriteLine($"Open ports on host {ipAddress}: {string.Join(", ", orderedOpenPorts)}");
            }
        }

        static IEnumerable<int> GetCommonPorts()
        {
            return new List<int> { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995 };
        }

        static void GetRouterIpAndSubnet(out string? routerIpAddress, out string? subnetMask)
        {
            routerIpAddress = null;
            subnetMask = null;

            try
            {
                NetworkInterface? activeInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(x => x.OperationalStatus == OperationalStatus.Up &&
                                x.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                x.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .FirstOrDefault(x =>
                    {
                        IPInterfaceProperties properties = x.GetIPProperties();
                        bool hasIpv4Gateway = properties.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                        bool hasIpv4Mask = properties.UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork && u.IPv4Mask != null);
                        return hasIpv4Gateway && hasIpv4Mask;
                    });

                if (activeInterface == null)
                {
                    throw new InvalidOperationException("No active IPv4 interface with gateway and subnet mask was found");
                }

                IPInterfaceProperties interfaceProperties = activeInterface.GetIPProperties();
                GatewayIPAddressInformation? gatewayAddress = interfaceProperties.GatewayAddresses
                    .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);
                if (gatewayAddress == null)
                {
                    throw new InvalidOperationException("Gateway address not found");
                }

                routerIpAddress = gatewayAddress.Address.ToString();
                subnetMask = interfaceProperties.UnicastAddresses
                    .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork && x.IPv4Mask != null)?
                    .IPv4Mask?
                    .ToString();
                if (string.IsNullOrWhiteSpace(subnetMask))
                {
                    throw new InvalidOperationException("Subnet mask not found");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving router IP address or subnet mask: {ex.Message}");
            }
        }

        static List<string>? GetIpAddresses(string routerIpAddress, string subnetMask)
        {
            try
            {
                IPAddress routerIp = IPAddress.Parse(routerIpAddress);
                IPAddress mask = IPAddress.Parse(subnetMask);

                uint routerIpUint = BitConverter.ToUInt32(routerIp.GetAddressBytes().Reverse().ToArray(), 0);
                uint maskUint = BitConverter.ToUInt32(mask.GetAddressBytes().Reverse().ToArray(), 0);

                uint subnetAddress = routerIpUint & maskUint;

                int hostBits = 32 - CountSetBits(maskUint); // Calculate the number of bits for the host portion
                if (hostBits < 0 || hostBits > 31)
                {
                    throw new InvalidOperationException($"Unsupported subnet mask {subnetMask}");
                }

                ulong hostCount = 1UL << hostBits;
                if (hostCount <= 2)
                {
                    return new List<string>();
                }

                ulong usableHostCount = hostCount - 2;
                const ulong maxHostsToGenerate = 1_000_000;
                if (usableHostCount > maxHostsToGenerate)
                {
                    throw new InvalidOperationException($"Subnet is too large to scan with this tool ({usableHostCount:N0} hosts)");
                }

                List<string> ipAddresses = new List<string>((int)usableHostCount);

                for (ulong i = 1; i < hostCount - 1; i++)
                {
                    uint ipUint = subnetAddress + (uint)i;
                    byte[] ipBytes = BitConverter.GetBytes(ipUint).Reverse().ToArray();
                    ipAddresses.Add(new IPAddress(ipBytes).ToString());
                }

                return ipAddresses;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing router IP address or subnet mask: {ex.Message}");
                return null;
            }
        }

        static int CountSetBits(uint n)
        {
            int count = 0;
            while (n > 0)
            {
                count += (int)(n & 1);
                n >>= 1;
            }
            return count;
        }
    }
}
