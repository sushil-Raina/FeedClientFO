// McxFeed.cpp : Defines the entry point for the console application.
//

#include "lzoconf.h"
#include "lzo1z.h"   

#include "winsock2.h"
#include "windows.h"
#include "Ws2tcpip.h"
#include "time.h"
#include "stdio.h"
#include "Stru.h"
#pragma comment(lib,"Ws2_32.lib")



HANDLE tHandle;




#pragma pack (push,2)
//---- FO ------ hi

typedef struct
{
	short iApiTcode;
	short iApiFuncId;
	long  LogTime;
	char  AlphaChar[2];
	short TransactionCode;
	short ErrorCode;
	char  Timestamp[8];
	char  Timestamp1[8];
	char  Timestamp2[8];
	short MessageLength;
}MESSAGE_HEADER;





typedef struct
{
	char InstrumentName[6];
	char Symbol[10];
	long ExpiryDate;
	long StrikePrice;
	char OptionType[2];
	short CALevel;
}CONTRACT_DESC;

typedef struct
{
	CONTRACT_DESC CONTRACT_DESC;
	short MarketType;
	long OpenPrice;
	long HighPrice;
	long LowPrice;
	long ClosingPrice;
	long TotalQuantityTraded;
	double TotalValueTraded;
	long PreviousClosePrice;
	long OpenInterest;
	long ChgOpenInterest;
	char Indicator[4];
}MKT_STATS_DATA;

typedef struct
{
	MESSAGE_HEADER MESSAGE_HEADER;
	char MessageType;
	char Reserved;
	short NumberOfRecords;
	MKT_STATS_DATA MKT_STATS_DATA[6];
}RP_MARKET_STATS;



typedef struct
{
	char cNetId[2];
	short iNoPackets;
	char cPackData[512];

}BcastPackData;

typedef struct
{
	short iCompLen;
	char cCompData[510];
}BcastCmpPacket;

typedef struct
{
	char Reserved1[2];
	char Reserved2[2];
	long LogTime;
	char AlphaChar[2];
	short TransactionCode;
	short ErrorCode;
	long BCSeqNo;
	char Reserved3;
	char Reserved4[3];
	char TimeStamp2[8];
	BYTE Filler[8];
	short MessageLength;
}BCAST_HEADER;

typedef struct
{
	BCAST_HEADER BCAST_HEADER;
	short NoOfRecords;
	INTERACTIVE_ONLY_MBP_DATA INTERACTIVE_ONLY_MBP_DATA[2];
}MS_BCAST_ONLY_MBP;

typedef struct
{
	long Token;
	short MarketType;
	long FillPrice;
	long FillVolume;
	long OpenInterest;
	long DayHiOI;
	long DayLoOI;

}ST_TICKER_INDEX_INFO;

typedef struct
{
	BCAST_HEADER BCAST_HEADER;
	short NumberofRecords;
	ST_TICKER_INDEX_INFO ST_TICKER_INDEX_INFO[17];
}MS_TICKER_TRADE_DATA;


typedef struct
{
	ST_INDICATOR ST_INDICATOR;
	long BuyVolume;
	long BuyPrice;
	long SellVolume;
	long SellPrice;
	long LastTradePrice;
	long LastTradeTime;
}ST_MKT_WISE_INFO;

typedef struct
{
	long Token;
	ST_MKT_WISE_INFO ST_MKT_WISE_INFO[3];
	long OpenInterest;
}ST_MARKET_WATCH_BCAST;

typedef struct
{
	MESSAGE_HEADER MESSAGE_HEADER;
	short NoOfRecords;
	ST_MARKET_WATCH_BCAST ST_MARKET_WATCH_BCAST[5];
}MS_BCAST_INQ_RESP_2;

typedef struct
{
	long TokenNo;
	long CurrentOI;
}OPEN_INTEREST;

typedef struct
{
	char Reserved1[2];
	char Reserved2[2];
	long LogTime;
	char MarketType[2];
	short TransactionCode;
	short NoOfRecords;
	char Reserved3[8];
	char TimeStamp[8];
	char Reserved4[8];
	short MessageLength;
	OPEN_INTEREST OPEN_INTEREST[58];
}CM_ASSSET_OI;


//--------------

#pragma pack (pop)




#pragma pack(push, 1)
typedef struct
{
	long			TokenNo;
	long			CloseTick;			// Ltp/10000.00			-do-
	long			BidTick[5];			// -1					best buyer
	long			AskTick[5];			// -1					best seller
	long 			BidSize[5];			// -1					buyerqty
	long 			AskSize[5];			// -1					sellerqty
	long			HighTick;			// High/10000.00			-do-
	long			LowTick;			// Low/10000.00			-do-
	long			OpenTick;			// Open/10000.00			-do-
	long			PreviousClose;		// -1					-do-
	long 			TradeVolume;		// -1					Ltq
	long 			TotalVolume;		// -1					Tvt
	long            LTT;
	long            D;
	long            T;
	double          TotalBidQty;
	double          TotalAskQty;

}SendPkt;

typedef struct
{
	long    lToken;
	SendPkt SndPkt;
	volatile long Status; //[1 : Info changed and Updated, Reader can read] [0 : Info already readed or Server is updating/UpdatingAgain]
	volatile long SubsFlag;
}ContractInfo;


#pragma pack(pop)


ContractInfo *pContract = NULL;
CRITICAL_SECTION  TCPCrit;
volatile long MTSFClose = 0;
volatile long FClose = 0;
WSADATA ws;

HANDLE hCatch = NULL;
HANDLE hSendEvent = NULL;
HANDLE hMulticast = NULL;

SOCKET  Sock;
struct sockaddr_in name;
unsigned char ttl = 2;
unsigned long ReTime = 500;
BOOL bAllow = TRUE;


#define   SIZE__SENDPKT_QUEUE  100000
int MaxToken = 150000;
volatile long SndPktA_Head = -1, SndPktA_Tail = -1;
int Que_TknNmbrs[SIZE__SENDPKT_QUEUE];



DWORD WINAPI Multicast(LPVOID pArg)
{
	Sock = INVALID_SOCKET;

Retry:
	InterlockedExchange(&MTSFClose, FClose);
	if (MTSFClose == 0)
	{
		Sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (Sock != INVALID_SOCKET)
		{
			memset((char *)&name, 0, sizeof(name));
			name.sin_family = PF_INET;
			name.sin_addr.s_addr = inet_addr("231.1.1.4");
			name.sin_port = htons(34343);
			if (setsockopt(Sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&ttl, sizeof(ttl)) != 0)
			{
				closesocket(Sock);
				Sleep(ReTime);
				goto Retry;
			}
			if (setsockopt(Sock, SOL_SOCKET, SO_BROADCAST, (char*)&bAllow, sizeof(bAllow)) != 0) // Configures a socket for sending broadcast data
			{
				closesocket(Sock);
				Sleep(ReTime);
				goto Retry;
			}

			SetEvent(hSendEvent);
		}
		else
		{
			closesocket(Sock);
			Sleep(ReTime);
			goto Retry;
		}
	}
	return  0;
}


//////////////////////////////////////////////////////Server Client Section- Starts///////////////////////////////////////////////

int __inline RecvPacketHeader(SOCKET ConnectSocket, char *Buffer, int Size)
{
	int Absorbed = 0;
PacketLoop:
	unsigned long bytesToRead = 0;
	if (ioctlsocket(ConnectSocket, FIONREAD, &bytesToRead) != SOCKET_ERROR)
	{
		if (bytesToRead > 0)
		{
			int recvpacket = recv(ConnectSocket, Buffer + Absorbed, Size - Absorbed, 0);
			Absorbed += recvpacket;
			if (Absorbed < Size)
			{
				goto PacketLoop;
			}
			return  0;
		}
		else
		{
			return -1;//if nothing to read
		}
	}
}

int __inline RecvPacket(SOCKET ConnectSocket, char *Buffer, int Size)
{
	int Absorbed = 0;
PacketLoop:
	int recvpacket = recv(ConnectSocket, Buffer + Absorbed, Size - Absorbed, 0);
	Absorbed += recvpacket;
	if (Absorbed < Size)
	{
		goto PacketLoop;
	}
	return  0;
}

int __inline RecvPacketDiscard(SOCKET ConnectSocket, char *Buffer, int Size)
{
	int Absorbed = 0;
PacketLoop:
	unsigned long bytesToRead = 0;
	int recvLen;
	if (ioctlsocket(ConnectSocket, FIONREAD, &bytesToRead) != SOCKET_ERROR)
	{
		if (bytesToRead <= 0)
			return WSAEWOULDBLOCK;

		recvLen = recv(ConnectSocket, Buffer + Absorbed, Size - Absorbed, 0);
		int lastErr = WSAGetLastError();
		if (recvLen == SOCKET_ERROR)
		{
			//if (lastErr == WSAEWOULDBLOCK)
			//{
			//	Sleep(10);
			//	goto PacketLoop;
			//}
			//else
			recvLen = 0;
			return lastErr;//0;
		}
		else if (recvLen == 0)
		{
			return recvLen;
		}
		else
		{
			Absorbed += recvLen;
			if (Absorbed < Size)
			{
				goto PacketLoop;
			}
		}
	}
	return recvLen;
}

int __inline SendPacket(SOCKET ConnectSocket, char *Buffer, int Size)
{

	int Absorbed = 0;
PacketLoop:
	int sendpacket = send(ConnectSocket, Buffer + Absorbed, Size - Absorbed, 0);

	if (SOCKET_ERROR == sendpacket)
	{
		int senderror = WSAGetLastError();
		return  0;
	}

	Absorbed += sendpacket;
	if (Absorbed < Size)
	{
		goto PacketLoop;
	}


	return  0;
}

DWORD WINAPI SockThread(LPVOID pArg)
{
	ServerInfo *pServerInfo = (ServerInfo *)pArg;

	volatile long lFClose;
	sockaddr_in SockAdder;

	char Buffer[1024];
	memset(Buffer, 0, sizeof(Buffer));

	int SockError = 0;
	WSADATA wsaData;

	if (NO_ERROR != WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		SockError = WSAGetLastError();
		return 1;
	}


ScktConnect:
	pServerInfo->Socket = INVALID_SOCKET;
	pServerInfo->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (pServerInfo->Socket == INVALID_SOCKET)
	{
		SockError = WSAGetLastError();
	}

	if (!InetPtonA(AF_INET, pServerInfo->IpAddress, &SockAdder.sin_addr.S_un.S_addr))
	{
		SockError = WSAGetLastError();
	}

	SockAdder.sin_family = AF_INET;
	SockAdder.sin_port = htons(pServerInfo->PortNo);
	if (SOCKET_ERROR == connect(pServerInfo->Socket, (SOCKADDR*)&SockAdder, sizeof(SockAdder)))
	{
		SockError = WSAGetLastError();
		printf("\rRetrying for connect... [ErrCode : %d]", SockError);
		closesocket(pServerInfo->Socket);
		pServerInfo->Socket = NULL;
		Sleep(1000);
		goto ScktConnect;
	}

	memset(Buffer, 0, sizeof(Buffer));

	PktHeader sHeader;
	PktHeader *pHeader = (PktHeader *)Buffer;
	memset(&sHeader, 0, sizeof(sHeader));
	sHeader.MagicNumber = 0xDD;
	sHeader.PacketType = 1;

	ssInit sInit;
	memset(&sInit, 0, sizeof(sInit));
	sInit.TerminalType = TERMINAL_TYPE_NSE_FO_FEED;

	SendPacket(pServerInfo->Socket, (char *)&sHeader, sizeof(sHeader));
	SendPacket(pServerInfo->Socket, (char *)&sInit, sizeof(sInit));

Loop:
	lFClose = InterlockedExchange(&FClose, FClose);

	if (!lFClose)
	{
		int recvLen = RecvPacketHeader(pServerInfo->Socket, (char *)&sHeader, sizeof(sHeader));

		// ----------------    queue work 


		if (recvLen == -1) // When NOT RECEIVED ANY PACKET 
		{
			//Send the feed packets, if other packets not received
			{
				//Send all packets from buffer 
				{
					int  Tmp_Front = SndPktA_Head;
					int  Tmp_Tail = SndPktA_Tail;


					//volatile long InterlockedExchange(&SndPktA_Head, SndPktA_Head);  // ; 
					//volatile long InterlockedExchange(&SndPktA_Tail, SndPktA_Tail);  // ;



				SendNextPaket:

					if (Tmp_Front != Tmp_Tail)
					{
						Tmp_Front = (Tmp_Front + 1) % SIZE__SENDPKT_QUEUE;
						volatile long  lStatus = 0; //[0 : Readed] [1 : Reading] [2 : Writing] [3 : Written]
						lStatus = InterlockedExchange(&(pContract + Que_TknNmbrs[Tmp_Front] - 1)->Status, (pContract + Que_TknNmbrs[Tmp_Front] - 1)->Status);

						if (lStatus == 3)
						{
							InterlockedExchange(&(pContract + Que_TknNmbrs[Tmp_Front] - 1)->Status, 1);

							sHeader.PacketType = 0x9;
							SendPacket(sServerInfo.Socket, (char *)&sHeader, sizeof(sHeader));
							SendPacket(sServerInfo.Socket, (char *)&((pContract + Que_TknNmbrs[Tmp_Front] - 1)->SndPkt), sizeof(SendPkt));

							InterlockedExchange(&(pContract + Que_TknNmbrs[Tmp_Front] - 1)->Status, 0);
						}

						SndPktA_Head = Tmp_Front; // InterlockedExchange(&SndPktA_Head, Tmp_Front); //
						printf("FO_Client   %5d  %10.4f    [%6d %6d]  [%ld]\n", (pContract + Que_TknNmbrs[Tmp_Front] - 1)->SndPkt.TokenNo, (pContract + Que_TknNmbrs[Tmp_Front] - 1)->SndPkt.CloseTick / 10000.0, Tmp_Front, Tmp_Tail, lStatus);

						goto SendNextPaket;
					}

				}

			}


		}

		//--------------------------------------




		else
		{
			// ----------------    queue work 

			switch (sHeader.PacketType)
			{
			case  0x2:

				ssInitResponseHeader sInitResponse;
				RecvPacket(pServerInfo->Socket, (char *)&sInitResponse, sizeof(ssInitResponseHeader));
				ssTerminalInfo sTerminalInfo;
				for (int i = 0; i < sInitResponse.NoofTerminals; i++)
				{
					RecvPacket(pServerInfo->Socket, (char *)&sTerminalInfo, sizeof(ssTerminalInfo));
					printf("Terminal id :- %d,%d", sTerminalInfo.Id, sTerminalInfo.Type);

					switch (sTerminalInfo.Type)
					{
					case  TERMINAL_TYPE_MASTER:
						printf(",Master Terminal\n");
						break;

					case  TERMINAL_TYPE_ADMIN:
						printf(",Admin Terminal\n");
						break;

					case  TERMINAL_TYPE_NSE_FO_FEED:
						printf(",Feed Terminal\n");
						break;

					case  TERMINAL_TYPE_SYNCTOOL:
						printf(",Synch Terminal\n");
						break;

					case  TERMINAL_TYPE_TRADER:
						printf(",Trader Terminal\n");
						break;

					case  TERMINAL_TYPE_MANUAL:
						printf(",Manual Terminal\n");
						break;

					default:
						printf(",Not Identified Terminal\n");
						break;
					}
				}


				sHeader.PacketType = 0x3;
				SendPacket(pServerInfo->Socket, (char *)&sHeader, sizeof(sHeader));

				ssLogin  sLogin;
				sLogin.Id = sTerminalInfo.Id;
				strcpy_s(sLogin.Password, "a1234567");
				strcpy_s(sLogin.NewPassword, "");

				SendPacket(pServerInfo->Socket, (char *)&sLogin, sizeof(sLogin));

				break;

			case 0x3:
				// Its not for Client Recv.
				break;

			case  0x4:

				ssLoginResponse sResponse;
				memset(&sResponse, 0, sizeof(sResponse));
				RecvPacket(pServerInfo->Socket, (char *)&sResponse, sizeof(sResponse));

				printf("Login Status Response :- %d -> %s \n", sResponse.LoginStatus, sResponse.LoginText);
				// Server - Client Ready to send packets.
				if (sResponse.LoginStatus == 1) //Success
				{
					printf("Event has been set\n");
					SetEvent(hSendEvent);
				}

				break;


			case 0x7:

				EnterCriticalSection(&TCPCrit);
				// Subscribe/Unsubscribe Token Response
				ssTokenHead sTokenHead;
				memset(&sTokenHead, 0, sizeof(sTokenHead));

				ssTokenRequestTail sTokenRequestTail;
				memset(&sTokenRequestTail, 0, sizeof(sTokenRequestTail));
				ssTokenResponseTail sTokenResponseTail;
				memset(&sTokenResponseTail, 0, sizeof(sTokenResponseTail));

				RecvPacket(pServerInfo->Socket, (char *)&sTokenHead, sizeof(sTokenHead));

				sHeader.PacketType = 0x8;
				SendPacket(pServerInfo->Socket, (char *)&sHeader, sizeof(sHeader));
				SendPacket(pServerInfo->Socket, (char *)&sTokenHead, sizeof(sTokenHead));
				switch (sTokenHead.RequestType)
				{
				case  0x1:
					for (int i = 0; i < sTokenHead.TokenCount; i++)
					{
						RecvPacket(pServerInfo->Socket, (char *)&sTokenRequestTail, sizeof(ssTokenRequestTail));
						InterlockedExchange(&(pContract + sTokenRequestTail.Token - 1)->SubsFlag, 1);
						sTokenResponseTail.Token = sTokenRequestTail.Token;
						sTokenResponseTail.ErrorCode = 1;
						SendPacket(pServerInfo->Socket, (char *)&sTokenResponseTail, sizeof(ssTokenResponseTail));
					}
					break;

				case  0x2:
					for (int i = 0; i < sTokenHead.TokenCount; i++)
					{
						RecvPacket(pServerInfo->Socket, (char *)&sTokenRequestTail, sizeof(ssTokenRequestTail));
						InterlockedExchange(&(pContract + sTokenRequestTail.Token - 1)->SubsFlag, 0);
						sTokenResponseTail.Token = sTokenRequestTail.Token;
						sTokenResponseTail.ErrorCode = 0;
						SendPacket(pServerInfo->Socket, (char *)&sTokenResponseTail, sizeof(ssTokenResponseTail));
					}
					break;

				default:

					break;
				}


				LeaveCriticalSection(&TCPCrit);

				break;

				break;

			case 0x8:

				break;

			case 0x9:

				break;

			default:

				break;
			}
		}

		goto Loop;
	}

	closesocket(pServerInfo->Socket);
	return 0;
}

//////////////////////////////////////////////////////Server Client Section- Ends///////////////////////////////////////////////



DWORD WINAPI CatchMulticast(LPVOID pArg)
{
	PktHeader sHeader;
	memset(&sHeader, 0, sizeof(sHeader));

	sHeader.MagicNumber = 0xDD;
	sHeader.PacketType = 0x9;

	//===================================


	SOCKET Socket;

	SendPkt  *SndPkt;

	IP_MREQ     Broadcast;
	sockaddr_in SenderAddr;
	sockaddr_in local;
	// SendPkt   sSendPkt;
	SYSTEMTIME LocalTime;

	const char optval = 1;
	BYTE iPacket[534];
	BYTE oPacket[10000];

	BcastPackData   *Packet;
	BcastCmpPacket  *CmpPacket;

	BCAST_HEADER         *BcastHeader = NULL;
	MS_BCAST_ONLY_MBP    *MBPPacket = (MS_BCAST_ONLY_MBP*)(oPacket + 8);
	int SenderAddrSize;

	SYSTEMTIME Time;
	lzo_uint oLen;


	memset(&SenderAddr, 0, sizeof(SenderAddr));
	memset(&Broadcast, 0, sizeof(Broadcast));
	SenderAddrSize = sizeof(SenderAddr);
	Socket = socket(AF_INET, SOCK_DGRAM, 0);
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_family = AF_INET;
	local.sin_port = htons(34330);   //  future //

									 // local.sin_port = 6791;     //// *** currency *** ////
	inet_pton(AF_INET, "233.1.2.5", &Broadcast.imr_multiaddr.s_addr); //"233.1.2.5"//293.255.255.255
	setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval));
	setsockopt(Socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&Broadcast, sizeof(Broadcast));

	Packet = (BcastPackData*)iPacket;
	CmpPacket = (BcastCmpPacket *)&Packet->cPackData;

	RP_MARKET_STATS   *RPMSPacket = (RP_MARKET_STATS *)(CmpPacket + 8);



	GetLocalTime(&Time);
	if (bind(Socket, (SOCKADDR*)&local, sizeof(local)) != SOCKET_ERROR)
	{
	PACKETLOOP:

		recvfrom(Socket, (char *)&iPacket, sizeof(iPacket), 0, (sockaddr *)&SenderAddr, &SenderAddrSize);

		switch (Packet->cNetId[0])
		{

		case  0x02:
			Packet->iNoPackets = htons(Packet->iNoPackets);
			CmpPacket->iCompLen = htons(CmpPacket->iCompLen);

			if (CmpPacket->iCompLen > 0)
			{
				memset(oPacket, 0, sizeof(oPacket));
				lzo1z_decompress((const unsigned char *)&CmpPacket->cCompData, CmpPacket->iCompLen, oPacket, &oLen, NULL);
				BcastHeader = (BCAST_HEADER*)(oPacket + 8);
			}
			else
			{
				BcastHeader = (BCAST_HEADER*)((const unsigned char *)&CmpPacket->cCompData + 8);
				goto PACKETLOOP;
			}


			BcastHeader->TransactionCode = htons(BcastHeader->TransactionCode);
			switch (BcastHeader->TransactionCode)
			{
			case 7208:

				MBPPacket->NoOfRecords = htons(MBPPacket->NoOfRecords);
				for (long i = 0; i < MBPPacket->NoOfRecords; i++)
				{
					MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token);

					if (MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token < 0 || MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token > MaxToken)
					{
						//ReAlloc SndPkts4AllTkns wrt CurrentToken, and then load the pkt details remove this continue.
						continue;
					}

					MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradedPrice = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradedPrice);
					MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradeTime = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradeTime);
					MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradeTime += 315513000;

					if (MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradeTime < 315513000)
					{
						continue;
					}

					long long LastTradeTime;
					{
						time_t t;
						t = (const time_t)MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradeTime;
						struct tm *ptm = localtime((const time_t *)&t);
						LastTradeTime = (ptm->tm_year + 1900) * 10000000000 + (ptm->tm_mon + 1) * 100000000 + ptm->tm_mday * 1000000 + ptm->tm_hour * 10000 + ptm->tm_min * 100 + ptm->tm_sec;
						//long Time = ptm->tm_hour * 100 + ptm->tm_min;
					}

					if (LastTradeTime % 1000000 < 91600 || MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradedPrice <= 0)
					{
						continue;
					}


					//if (SendKey == true)
					{
						// Check here, if not subscribed then donot allow to enter in the queue						
						volatile long  lSubsFlag = 0;
						lSubsFlag = InterlockedExchange(&(pContract + MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token - 1)->SubsFlag, (pContract + MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token - 1)->SubsFlag);

						if (lSubsFlag == 1)
						{
							volatile long  lStatus = 0; //[0 : Readed] [1 : Reading] [2 : Writing] [3 : Written]
							lStatus = InterlockedExchange(&(pContract + MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token - 1)->Status, (pContract + MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token - 1)->Status);

							if (lStatus == 0 || lStatus == 3)
							{
								if (((SndPktA_Tail + 1) == SndPktA_Head)
									||
									(SndPktA_Head == 0 && SndPktA_Tail == (SIZE__SENDPKT_QUEUE - 1))
									)
								{//The queue is full
									SndPktA_Head = -1;
								}

								InterlockedExchange(&(pContract + MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token - 1)->Status, 2);
								SndPkt = (&(pContract + MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token - 1)->SndPkt);

								//Populate the Fields
								{
									GetLocalTime(&LocalTime);

									SndPkt->CloseTick = (MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradedPrice) * 100;    // Ltp/100.00            -do-
									SndPkt->OpenTick = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].OpenPrice) * 100;
									SndPkt->HighTick = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].HighPrice) * 100;
									SndPkt->LowTick = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LowPrice) * 100;
									SndPkt->PreviousClose = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].ClosingPrice) * 100;
									SndPkt->TradeVolume = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].LastTradeQuantity);          // -1                    Ltq
									SndPkt->TotalVolume = ntohl(MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].VolumeTradedToday);          // -1                    Tvt
									SndPkt->TokenNo = (MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token);

									// LastTradedPrice|OpenPrice|HighPrice|LowPrice|ClosingPrice|LastTradeQuantity|VolumeTradedToday|Token|lExpiryDate


									MBP_INFORMATION *MBP = (MBP_INFORMATION *)&MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].MBPInfo;//  RecordBuffer;

																															   //Pending : Check for PRice, multipy 100 required or not  
									SndPkt->BidSize[0] = htonl((MBP + 0)->Quantity);
									SndPkt->BidSize[1] = htonl((MBP + 1)->Quantity);
									SndPkt->BidSize[2] = htonl((MBP + 2)->Quantity);
									SndPkt->BidSize[3] = htonl((MBP + 3)->Quantity);
									SndPkt->BidSize[4] = htonl((MBP + 4)->Quantity);

									SndPkt->BidTick[0] = htonl((MBP + 0)->Price) * 100;
									SndPkt->BidTick[1] = htonl((MBP + 1)->Price) * 100;
									SndPkt->BidTick[2] = htonl((MBP + 2)->Price) * 100;
									SndPkt->BidTick[3] = htonl((MBP + 3)->Price) * 100;
									SndPkt->BidTick[4] = htonl((MBP + 4)->Price) * 100;

									SndPkt->AskSize[0] = htonl((MBP + 5)->Quantity);
									SndPkt->AskSize[1] = htonl((MBP + 6)->Quantity);
									SndPkt->AskSize[2] = htonl((MBP + 7)->Quantity);
									SndPkt->AskSize[3] = htonl((MBP + 8)->Quantity);
									SndPkt->AskSize[4] = htonl((MBP + 9)->Quantity);

									SndPkt->AskTick[0] = htonl((MBP + 5)->Price) * 100;
									SndPkt->AskTick[1] = htonl((MBP + 6)->Price) * 100;
									SndPkt->AskTick[2] = htonl((MBP + 7)->Price) * 100;
									SndPkt->AskTick[3] = htonl((MBP + 8)->Price) * 100;
									SndPkt->AskTick[4] = htonl((MBP + 9)->Price) * 100;

									//printf("%d, %15f    [%4d %4d] \n", SndPktArr[Idx_Tail].TokenNo, SndPktArr[Idx_Tail].CloseTick/10000.0, SndPktA_Head, SndPktA_Tail);

								}

								InterlockedExchange(&(pContract + MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token - 1)->Status, 3);
								int Idx_Tail = (SndPktA_Tail + 1) % SIZE__SENDPKT_QUEUE;
								Que_TknNmbrs[Idx_Tail] = MBPPacket->INTERACTIVE_ONLY_MBP_DATA[i].Token;
								SndPktA_Tail = Idx_Tail;
							}
						}
					}

				}

				break;
			}

			break;
		}

		goto PACKETLOOP;
	}

	//free(Contract);
	return 0;
}

DWORD WINAPI ContractReader(LPVOID pArg)
{
	pContract = (ContractInfo *)calloc(MaxToken, sizeof(ContractInfo));


	/////////////////////// Client Server Code - Start////////////////
	hSendEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

	//Delete Later  
	//SetEvent(hSendEvent);

	memset(&sServerInfo, 0, sizeof(sServerInfo));
	strcpy(sServerInfo.IpAddress, "192.168.1.146");//Rekha 
	sServerInfo.PortNo = 3010;
	hSock = CreateThread(NULL, NULL, &SockThread, &sServerInfo, NULL, NULL);
	WaitForSingleObject(hSendEvent, INFINITE);
	////////////////////// Client Sever Code - Ends///////////////////

	printf("Attempting Catch Multicast\n");
	hCatch = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&CatchMulticast, NULL, NULL, NULL);
	WaitForSingleObject(hCatch, INFINITE);
	WaitForSingleObject(hSock, INFINITE);

	CloseHandle(hSendEvent);
	free(pContract);
	return 0;
}

int main()
{
	HWND consoleWindow = GetConsoleWindow();
	SetWindowPos(consoleWindow, 0, 1240, 0, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
	//----------------------------

	memset(&TCPCrit, 0, sizeof(TCPCrit));
	InitializeCriticalSection(&TCPCrit);

	WSAStartup(MAKEWORD(2, 2), &ws);

	tHandle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&ContractReader, NULL, NULL, NULL);
	WaitForSingleObject(tHandle, INFINITE);

	DeleteCriticalSection(&TCPCrit);
	return 0;
}

