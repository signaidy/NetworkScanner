﻿using System;
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
            string baseIpAddress = GetBaseIpAddress(routerIpAddress, subnetMask);
            if (baseIpAddress == null)
            {
                Console.WriteLine("Unable to parse router IP address or subnet mask. Exiting...");
                return;
            }

            Console.WriteLine($"Scanning network for active hosts (based on {baseIpAddress} subnet)...");

            // Perform ICMP ping sweep on the network
            int startRange = GetStartRange(subnetMask);;
            int endRange = GetEndRange(subnetMask);

            List<Task> tasks = new List<Task>();

            for (int i = startRange; i <= endRange; i++)
            {
                string ipAddress = $"{string.Join(".", baseIpAddress.Split('.').Take(3))}.{i}";

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

        static string GetBaseIpAddress(string routerIpAddress, string subnetMask)
        {
            try
            {
                IPAddress routerIp = IPAddress.Parse(routerIpAddress);
                IPAddress mask = IPAddress.Parse(subnetMask);

                byte[] routerBytes = routerIp.GetAddressBytes();
                byte[] maskBytes = mask.GetAddressBytes();

                byte[] baseBytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    baseBytes[i] = (byte)(routerBytes[i] & maskBytes[i]);
                }

                return new IPAddress(baseBytes).ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing router IP address or subnet mask: {ex.Message}");
                return null;
            }
        }

        static int GetStartRange(string subnetMask)
        {
            try
            {
                IPAddress mask = IPAddress.Parse(subnetMask);
                byte[] maskBytes = mask.GetAddressBytes();

                // Calculate the network address
                byte[] networkAddressBytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    networkAddressBytes[i] = (byte)(maskBytes[i] & maskBytes[i]);
                }

                return BitConverter.ToInt32(networkAddressBytes.Reverse().ToArray(), 0) + 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing subnet mask: {ex.Message}");
                return 1;
            }
        }

        static int GetEndRange(string subnetMask)
        {
            try
            {
                IPAddress mask = IPAddress.Parse(subnetMask);
                byte[] maskBytes = mask.GetAddressBytes();

                int endRange = 0;
                for (int i = 0; i < 4; i++)
                {
                    endRange += 255 - maskBytes[i];
                }

                return endRange;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error parsing subnet mask: {ex.Message}");
                return 255;
            }
        }
    }
}