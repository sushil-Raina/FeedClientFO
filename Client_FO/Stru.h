
//////////////////////////////////////////////////////Server Client Section///////////////////////////////////////////////

#define TERMINAL_TYPE_MASTER       1
#define TERMINAL_TYPE_ADMIN        2
#define TERMINAL_TYPE_MCX_FEED     3
#define TERMINAL_TYPE_SYNCTOOL     4
#define TERMINAL_TYPE_NSE_CM_FEED  5
#define TERMINAL_TYPE_NSE_FO_FEED  6
#define TERMINAL_TYPE_NSE_CDS_FEED 7
#define TERMINAL_TYPE_TRADER       8
#define TERMINAL_TYPE_MANUAL       9
#define TERMINAL_TYPE_INPUTPOS    10 //multicast




#pragma pack (push,2)
//---- FO ------ 

typedef struct
{
	unsigned char Reserved1 : 4;
	unsigned char Sell : 1;
	unsigned char Buy : 1;
	unsigned char LastTradeLess : 1;
	unsigned char LastTradeMore : 1;
	char  Reserved2;
}ST_INDICATOR;

typedef struct
{
	long Quantity;
	long Price;
	short NumberOfOrders;
	short BbBuySellFlag;
}MBP_INFORMATION;

typedef struct
{
	long Token;
	short BookType;
	short TradingStatus;
	long VolumeTradedToday;
	long LastTradedPrice;
	char NetChangeIndicator;
	long NetPriceChangeFromClosingPrice;
	long LastTradeQuantity;
	long LastTradeTime;
	long AverageTradePrice;
	short AuctionNumber;
	short AuctionStatus;
	short InitiatorType;
	long InitiatorPrice;
	long InitiatorQuantity;
	long AuctionPrice;
	long AuctionQuantity;

	MBP_INFORMATION MBPInfo[10];

	short  BbTotalBuyFlag;
	short BbTotalSellFlag;
	double TotalBuyQuantity;
	double TotalSellQuantity;
	ST_INDICATOR ST_INDICATOR;
	long ClosingPrice;
	long OpenPrice;
	long HighPrice;
	long LowPrice;
}INTERACTIVE_ONLY_MBP_DATA;


#pragma pack(pop)
 
 
#pragma pack(push,1)

typedef struct
{
	char IpAddress[16];
	int PortNo;
	SOCKET Socket;
}ServerInfo;

typedef struct  // ClientSends // Server Checks
{
	short	MagicNumber; // Magic Number = 0x069FFA
	unsigned short	PacketType;
}PktHeader;
 
typedef struct
{
	int TerminalType; //client to send what type of terminal it is.
}ssInit;

typedef struct
{
	int NoofTerminals; //no. of terminals available of type = TerminalType in init packet
}ssInitResponseHeader;

typedef struct
{
	int   Id;
	int   Type;
	char  Name[100];
	int   LoginStatus;// 1- logged in , 2 - not logged in but enabled, 3 - disabled, 4 - password expired
	int   FeatsMap1; //features map
	int   FeatsMap2;// Reserved
	int   PwdUpdateDate;
	int   WrongPwdCount;
}ssTerminalInfo;

//only new_ssTerminal_Head packet should be sent to client, new_ssTerminal_Pwd packet only for binary file + local memory
typedef struct
{
	char  CurrentPass[20];
	char  Pass1[20];
	char  Pass2[20];
	char  Pass3[20];
	char  Pass4[20];
	char  Pass5[20];
}ssTerminalPwd;

typedef struct  //Packet Type 3 ..
{
	int   Id;// T1
	char  Password[10];//" a123456"
	char  NewPassword[10];// ""
}ssLogin;

typedef struct
{
	int    LoginStatus;  //0 - Success 1 - NewUser .Please change Password 2- Wrong Password 3- New Password similar as last 5 passwords 4- User Disabled.Contact . 
	char   LoginText[200]; // Coressponding Messages
						   //int    NoofTokens;  // 5
}ssLoginResponse;

typedef struct
{
	int RequestType;//1 - new terminal, 2 - delete terminal, 3 - update terminal name only , 4- reset password
	int TerminalId;
	int TerminalType;
	char TerminalName[100];
}ssTerminalRequest;

typedef struct
{
	ssTerminalRequest request;
	int RequestStatus; //0 - success, 1 - fail
	int ErrorCode;
}ssTerminalResponse;

typedef struct
{
	int PacketType; // 2
	int TerminalId;// T4 - 4
}ssTerminalSelect;

//Feed Request
typedef struct
{
	int RequestType; //1 - Subscribe token , 2 - Unsubscribe token
	int ExchangeId;
	int SegmentId;
	int TokenCount;
}ssTokenHead;

typedef struct
{
	int Token;
}ssTokenRequestTail;

typedef struct
{
	int Token;
	int ErrorCode;   // [1: Success] [2 : InvalidToken] [3 : Already Subscribed/Unsubscribed]
}ssTokenResponseTail;


//typedef struct
//{
//	unsigned char Reserved1 : 4;
//	unsigned char Sell : 1;
//	unsigned char Buy : 1;
//	unsigned char LastTradeLess : 1;
//	unsigned char LastTradeMore : 1;
//	char  Reserved2;
//}ST_INDICATOR;

//
//typedef struct
//{
//	long Quantity;
//	long Price;
//	short NumberOfOrders;
//	short BbBuySellFlag;
//}MBP_INFORMATION;

//typedef struct
//{
//	long Token;
//	short BookType;
//	short TradingStatus;
//	long VolumeTradedToday;
//	long LastTradedPrice;
//	char NetChangeIndicator;
//	long NetPriceChangeFromClosingPrice;
//	long LastTradeQuantity;
//	long LastTradeTime;
//	long AverageTradePrice;
//	short AuctionNumber;
//	short AuctionStatus;
//	short InitiatorType;
//	long InitiatorPrice;
//	long InitiatorQuantity;
//	long AuctionPrice;
//	long AuctionQuantity;
//
//	MBP_INFORMATION MBPInfo[10];
//
//	short  BbTotalBuyFlag;
//	short BbTotalSellFlag;
//	double TotalBuyQuantity;
//	double TotalSellQuantity;
//	ST_INDICATOR ST_INDICATOR;
//	long ClosingPrice;
//	long OpenPrice;
//	long HighPrice;
//	long LowPrice;
//}INTERACTIVE_ONLY_MBP_DATA;

typedef struct
{
	int FeedType;
	int FeedCount;
}ssFeedHead;


typedef struct
{
	char IndexName[21];
	long IndexValue;
	long HighIndexValue;
	long LowIndexValue;
	long OpeningIndex;
	long ClosingIndex;
	long PercentChange;
	long YearlyHigh;
	long YearlyLow;
	long NoOfUpmoves;
	long NoOfDownmoves;
	double MarketCapitalisation;
	char NetChangeIndicator;
	char Reserved;
}MS_INDICES;

typedef struct
{
	INTERACTIVE_ONLY_MBP_DATA FeedPack;
}ssFeedTail_1;

typedef struct
{
	MS_INDICES FeedPack;
}ssFeedTail_2;

#pragma pack(pop)


HANDLE hSock;
ServerInfo sServerInfo;

