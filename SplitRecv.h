#pragma once
#include <Windows.h>
#include <stdio.h>
#include <vector>
#define PACKAGEFIELDSIZE 0x1000

#define quint8 unsigned char
#define quint16 unsigned short
#define quint32 unsigned int
#define quint64 unsigned long long
#define qint64 long long
#define qint32 int
#define qint16 short

void hexdump(void *mem, size_t len, WORD wAttributes = 0x0F);

union __m128i
{
	char m128i_i8[16];
	short m128i_i16[8];
	int m128i_i32[4];
	long long m128i_i64[2];
	unsigned char m128i_u8[16];
	unsigned short m128i_u16[8];
	unsigned int m128i_u32[4];
	unsigned long long m128i_u64[2];
};

struct SBuffer
{
	char *m_Buffer;
	size_t m_size = 0;
};

class CPackageField
{
public:
	uint32_t m_Size;
	char m_Buffer[PACKAGEFIELDSIZE];
};

class CBuffer
{
public:
	qint64 m_socket;
	char *m_buffer;
	size_t m_Index = 0;
	CBuffer(char *buffer, qint64 socket = 0)
	{
		m_buffer = buffer;
		m_socket = socket;
	};
	template <class T>
	CBuffer &operator>>(T &v)
	{

		size_t len = sizeof(T);
		__try
		{
			v = *((T *)((DWORD64)m_buffer + m_Index));
			m_Index += len;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("异常:CBuffer &operator>>(T &v)\n");
		}
		if (len == 1)
		{
			hexdump(&v, len, 6);
		}
		else if (len == 2)
		{
			hexdump(&v, len, 6);
			v = htons(v);
		}
		else if (len == 4)
		{
			hexdump(&v, len, 6);
			v = htonl(v);
		}
		return *this;
	}

	CBuffer &operator>>(SBuffer &v)
	{
		v.m_Buffer = (char *)((DWORD64)m_buffer);
		hexdump(v.m_Buffer + m_Index, v.m_size, 6);
		m_Index += v.m_size;
		return *this;
	}

	template <class T>
	T read()
	{
		size_t len = sizeof(T);
		T v;
		__try
		{
			v = *((T *)((DWORD64)m_buffer + m_Index));
			m_Index += len;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			printf("异常:CBuffer &operator>>(T &v)\n");
		}
		if (len == 1)
		{
			hexdump(&v, len, 6);
		}
		else if (len == 2)
		{
			hexdump(&v, len, 6);
			v = htons(v);
		}
		else if (len == 4)
		{
			hexdump(&v, len, 6);
			v = htonl(v);
		}
		else
		{
			hexdump(&v, len, 6);
		}
		return v;
	}

	void read(qint64 size)
	{
		hexdump(m_buffer + m_Index , size, 6);
		m_Index += size;
	}

	void read(void * buffer , qint64 size)
	{
	
		hexdump(m_buffer + m_Index , size, 6);
		memcpy_s(buffer , size , m_buffer + m_Index , size);
		m_Index += size;

	}

	void readString();
	quint16 ReadData();
	quint64 ReadData_0();
	quint64 ReadData_1();
	void ReadData_2();
	void ReadData_3();
	void ReadData_4();

	void 解析收包();
	void Recv_Link1_02();
	void Recv_Link1_04();
	void Recv_Link1_13();
	void Recv_Link1_15();
	void Recv_Link1_14();
	void Recv_Link1_19();

	void Recv_Link2_0f();
	void Recv_Link2_10();
	void Recv_Link2_13();
	void Recv_Link2_15();
	void Recv_Link2_3b();
	void Recv_Link2_143();
	void Recv_Link2_214();
	void Recv_Link2_215();
	void Recv_Link2_274();
	void Recv_Link2_216();
	void Recv_Link2_0a();
	void Recv_Link2_144();
	void Recv_Link2_149();
	void Recv_Link2_14b();
	void Recv_Link2_1a3();
	void Recv_Link2_142();
	void Recv_Link2_14c();
	void Recv_Link2_14d();
	void Recv_Link2_173();
};

extern std::vector<CPackageField *> g_收包字段数组;
extern std::vector<CPackageField *> g_收包字段数组;
extern bool g_收集解密字段;
extern int g_解密字段循环次数;