// NS-101 guest-only fixture, built with the trusted Windows Framework compiler.
using System;
using System.Net;
using System.Net.Sockets;

internal static class NetSentinelLabTcpClient
{
    private const string LabIp = "__LAB_IP__";
    private const int LabPort = __LAB_PORT__;

    private static int Main(string[] args)
    {
        IPAddress address;
        if (args.Length != 0 || !IPAddress.TryParse(LabIp, out address)
            || address.AddressFamily != AddressFamily.InterNetwork
            || address.ToString() != LabIp || LabPort < 1024 || LabPort > 65535)
            return 64;
        byte[] bytes = address.GetAddressBytes();
        if (!(bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)))
            return 64;
        try
        {
            using (Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                client.SendTimeout = 5000;
                client.ReceiveTimeout = 5000;
                IAsyncResult connecting = client.BeginConnect(new IPEndPoint(address, LabPort), null, null);
                using (connecting.AsyncWaitHandle)
                {
                    if (!connecting.AsyncWaitHandle.WaitOne(5000))
                        return 4;
                    client.EndConnect(connecting);
                }
                if (client.Send(new byte[] { 0x4e }) != 1)
                    return 5;
                byte[] reply = new byte[1];
                if (client.Receive(reply) != 1 || reply[0] != 0x4e)
                    return 5;
            }
            Console.WriteLine("NS101_CONNECTED");
            return 0;
        }
        catch (SocketException error)
        {
            Console.WriteLine("NS101_SOCKET_ERROR:" + error.ErrorCode);
            return error.SocketErrorCode == SocketError.AccessDenied ? 3 : 5;
        }
        catch (Exception)
        {
            return 5;
        }
    }
}
