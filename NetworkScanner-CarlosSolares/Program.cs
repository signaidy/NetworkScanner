using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Linq;
using System.Threading.Tasks;

namespace NetworkScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Network Scanner");

            // Record the start time
            Stopwatch stopwatch = Stopwatch.StartNew();

            // Get the IP address and subnet mask of the Wi-Fi router
            string routerIpAddress, subnetMask;
            GetRouterIpAndSubnet(out routerIpAddress, out subnetMask);
            if (routerIpAddress == null || subnetMask == null)
            {
                Console.WriteLine("Unable to retrieve router IP address or subnet mask. Exiting...");
                return;
            }

            Console.WriteLine($"Wi-Fi router IP address: {routerIpAddress}");
            Console.WriteLine($"Subnet mask: {subnetMask}");

            // Define the range of IP addresses to scan based on the subnet mask
            List<string> ipAddresses = GetIpAddresses(routerIpAddress, subnetMask);
            if (ipAddresses == null || ipAddresses.Count == 0)
            {
                Console.WriteLine("No IP addresses to scan. Exiting...");
                return;
            }

            Console.WriteLine($"Scanning network for active hosts...");

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
                Ping ping = new Ping();
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
            List<int> openPorts = new List<int>();

            Parallel.ForEach(GetCommonPorts(), port =>
            {
                try
                {
                    using (TcpClient tcpClient = new TcpClient())
                    {
                        tcpClient.Connect(ipAddress, port);
                        openPorts.Add(port);
                    }
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

            if (openPorts.Any())
            {
                Console.WriteLine($"Open ports on host {ipAddress}: {string.Join(", ", openPorts)}");
            }
        }

        static IEnumerable<int> GetCommonPorts()
        {
            return new List<int> { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995 };
        }

        static void GetRouterIpAndSubnet(out string routerIpAddress, out string subnetMask)
        {
            routerIpAddress = null;
            subnetMask = null;
            try
            {
                NetworkInterface wifiInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(x => x.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 && x.OperationalStatus == OperationalStatus.Up);

                if (wifiInterface == null)
                {
                    throw new InvalidOperationException("Wi-Fi interface not found or not operational");
                }

                IPInterfaceProperties wifiIpProperties = wifiInterface.GetIPProperties();
                GatewayIPAddressInformation gatewayAddress = wifiIpProperties.GatewayAddresses.FirstOrDefault();
                if (gatewayAddress == null)
                {
                    throw new InvalidOperationException("Gateway address not found");
                }

                routerIpAddress = gatewayAddress.Address.ToString();
                subnetMask = wifiIpProperties.UnicastAddresses.FirstOrDefault(x => x.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.IPv4Mask.ToString();
                if (subnetMask == null)
                {
                    throw new InvalidOperationException("Subnet mask not found");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving router IP address or subnet mask: {ex.Message}");
            }
        }

        static List<string> GetIpAddresses(string routerIpAddress, string subnetMask)
        {
            try
            {
                IPAddress routerIp = IPAddress.Parse(routerIpAddress);
                IPAddress mask = IPAddress.Parse(subnetMask);

                uint routerIpUint = BitConverter.ToUInt32(routerIp.GetAddressBytes().Reverse().ToArray(), 0);
                uint maskUint = BitConverter.ToUInt32(mask.GetAddressBytes().Reverse().ToArray(), 0);

                uint subnetAddress = routerIpUint & maskUint;

                int hostBits = 32 - CountSetBits(maskUint); // Calculate the number of bits for the host portion

                int hostCount = 1 << hostBits; // Use the correct type for the left shift operation

                List<string> ipAddresses = new List<string>();

                for (uint i = 1; i < hostCount - 1; i++)
                {
                    uint ipUint = subnetAddress + i;
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
