# NetworkScanner

Console-based local network scanner built with .NET 8.

It discovers active IPv4 hosts in the local subnet (based on an active interface with gateway + mask), then checks a small set of common TCP ports for each responsive host.

## Project Structure

- `NetworkScanner.sln`: Solution file.
- `NetworkScanner-CarlosSolares/Program.cs`: Main scanner implementation.
- `NetworkScanner-CarlosSolares/NetworkScanner-CarlosSolares.csproj`: Project file.

## Requirements

- .NET SDK 8.0+
- A connected active IPv4 network interface with gateway and subnet mask
- Permission to send ICMP echo requests and open TCP connections on your network

## Build

```powershell
dotnet build NetworkScanner.sln
```

## Run

```powershell
dotnet run --project .\NetworkScanner-CarlosSolares\NetworkScanner-CarlosSolares.csproj
```

## What It Does

1. Finds an active IPv4 interface (excluding loopback/tunnel) with gateway and subnet mask.
2. Reads gateway IP and subnet mask from that interface.
3. Generates all usable host IPs in the subnet.
4. Pings each host (100 ms timeout).
5. For hosts that respond, scans these common TCP ports (300 ms timeout per connect attempt):
   - `21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995`
6. Prints open ports and total scan time.

## Notes and Current Limitations

- Host discovery (ping sweep) runs sequentially, so larger subnets may take longer.
- The tool limits generated host lists to `1,000,000` addresses for practicality.

## Safety

Only scan networks and hosts you own or are explicitly authorized to test.
