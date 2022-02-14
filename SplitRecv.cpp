#include "SplitRecv.h"
#define HEXDUMP_COLS 16
std::vector<CPackageField *> g_收包字段数组;
bool g_收集解密字段 = false;
int g_解密字段循环次数 = 25; //11

void hexdump(void *mem, size_t len, WORD wAttributes)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wAttributes);
    size_t i, j;
    printf("-------------------------------------------------------------------------------\n");
    for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if (i % HEXDUMP_COLS == 0)
        {
            printf("| 0x%04X | ", (unsigned int)i);
        }

        /* print hex data */
        if (i < len)
        {
            printf("%02x ", 0xFF & ((char *)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            printf("   ");
        }

        /* print ASCII dump */
        if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            printf("| ");
            for (j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if (j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if (isprint(((char *)mem)[j])) /* printable char */
                {
                    putchar(0xFF & ((char *)mem)[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            printf(" |\n");
        }
    }
    printf("-------------------------------------------------------------------------------\n");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x0F);
}

void CBuffer::解析收包()
{
    WORD PacketID = htons(*(WORD *)(this->m_buffer));
    this->m_Index += 2;
    if (PacketID == 0x210)
    {
        return;
    }

    // if (PacketID != 0x14c || PacketID != 0x216)
    //     return;

    switch (PacketID)
    {
    case 0x2:
    {
        Recv_Link1_02();
        break;
    }
    case 0x4:
    {
        Recv_Link1_04();
        break;
    }
    case 0x5:
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
        printf("\nRECV ID:%x SOCKET:%llx\n", 0x5, m_socket);
        break;
    }
    case 0xa:
    {
        Recv_Link2_0a();
        break;
    }
    case 0x13:
    {
        // static bool isb = false;
        // if (!isb)
        // {
        //     Recv_Link1_13();
        //     isb = true;
        // }
        // else
        // {
        //     Recv_Link2_13();
        // }

        break;
    }
    case 0x15:
    {
        // static bool isb15 = false;
        // if (!isb15)
        // {
        //     Recv_Link1_15();
        //     isb15 = true;
        // }
        // else
        // {
        //     Recv_Link2_15();
        // }
        break;
    }
    case 0x19:
    {
        Recv_Link1_19();
        break;
    }
    case 0x3b:
    {
        Recv_Link2_3b();
        break;
    }
    case 0xf:
        break;
    case 0x10:
    {
        Recv_Link2_10();
        break;
    }
    case 0x142:
    {
        Recv_Link2_142();
        break;
    }
    case 0x143:
    {
        Recv_Link2_143();
        break;
    }
    case 0x149:
    {
        Recv_Link2_149();
        break;
    }
    case 0x14c:
    {
        Recv_Link2_14c();
        break;
    }
    case 0x14d:
    {
        Recv_Link2_14d();
        break;
    }
    case 0x1a3:
    {
        Recv_Link2_1a3();
        break;
    }
    case 0x144:
    {
        Recv_Link2_144();
        break;
    }
    case 0x173:
    {
        Recv_Link2_173();
        break;
    }
    case 0x14b:
    {
        Recv_Link2_14b();
        break;
    }
    case 0x210:
        break;
    case 0x215:
    {
        Recv_Link2_215();
        break;
    }
    case 0x216:
    {
        Recv_Link2_216();
        break;
    }
    case 0x214:
        Recv_Link2_214();
        return;
    case 0x274:
    {
        Recv_Link2_274();
        break;
    }

    default:
        break;
    }
    printf("\n");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x2);
    printf("RECV自动解析 ID:%x SOCKET:%llx\n", PacketID, m_socket);
    printf("-------------------------------------------------------------------------------\n");

    g_收集解密字段 = true;
    g_解密字段循环次数 = 150;
}

void CBuffer::Recv_Link2_143()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV ID:%x SOCKET:%llx\n", 0x143, m_socket);

    ReadData();
    quint16 v4 = read<quint16>();
    if ((v4 & 0x80u) != 0)
    {
        read<quint32>();
    }

    ReadData_1();
    ReadData_1();
    ReadData_1();
    ReadData_1();

    read<quint16>();
    read<quint16>();
}

void CBuffer::Recv_Link2_214()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV ID:%x SOCKET:%llx\n", 0x214, m_socket);

    ReadData();
    read<quint32>();

    ReadData_3();
}

void CBuffer::Recv_Link2_215()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV ID:%x SOCKET:%llx\n", 0x215, m_socket);

    ReadData();
    ReadData_3();
}

void CBuffer::Recv_Link2_0a()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0xa, m_socket);

    readString();

    readString();

    readString();

    read<quint16>();
    read<quint8>();
    read<quint8>();

    quint8 size = read<quint8>();

    for (WORD i = 0; i < size; i++)
    {
        read<quint32>();
        ReadData_3();
    }
}

void CBuffer::readString()
{
    WORD len;
    *this >> len;
    SBuffer buffer;
    buffer.m_size = len * 2;
    *this >> buffer;
}

void CBuffer::Recv_Link2_144()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x144, m_socket);

    read<quint32>();
    read<quint32>();
    read<quint16>();
}

quint16 CBuffer::ReadData()
{
    read<quint32>();
    read<quint32>();
    return read<quint16>();
}

quint64 CBuffer::ReadData_0()
{
    __int8 v2;          // bl
    __m128i v4;         // [rsp+20h] [rbp-10h] BYREF
    __m128i v5;         // [rsp+58h] [rbp+28h] BYREF
    unsigned __int8 v6; // [rsp+68h] [rbp+38h] BYREF

    v5.m128i_i8[0] = read<quint8>();
    v2 = v5.m128i_i8[0];
    if (v5.m128i_i8[0] >= 0)
        return v5.m128i_u8[0];
    v5.m128i_i8[0] = 0;
    if ((v2 & 0xC0) == 0x80)
    {
        v5.m128i_u8[0] = read<quint8>();
        return v5.m128i_u8[0] | ((unsigned __int8)(v2 & 0x3F) << 8);
    }
    else
    {
        v5.m128i_i8[8] = 0;
        if ((v2 & 0xE0) == 0xC0)
        {
            v5.m128i_u8[0] = read<quint8>();
            v5.m128i_u8[8] = read<quint8>();
            return v5.m128i_u8[8] | ((v5.m128i_u8[0] | ((unsigned __int8)(v2 & 0x1F) << 8)) << 8);
        }
        else
        {
            v6 = 0;
            if ((v2 & 0xF0) == 0xE0)
            {
                v5.m128i_u8[0] = read<quint8>();
                v5.m128i_u8[8] = read<quint8>();
                v6 = read<quint8>();

                return v6 | ((v5.m128i_u8[8] | ((v5.m128i_u8[0] | ((unsigned __int8)(v2 & 0x1F) << 8)) << 8)) << 8);
            }
            else
            {

                v5.m128i_u8[0] = read<quint8>();
                v5.m128i_u8[8] = read<quint8>();
                v6 = read<quint8>();
                v4.m128i_i8[0] = read<quint8>();
                return v4.m128i_u8[0] | ((v6 | ((v5.m128i_u8[8] | (v5.m128i_u8[0] << 8)) << 8)) << 8);
            }
        }
    }
}

quint64 CBuffer::ReadData_1()
{
    __int8 v2;          // bl
    __int64 result;     // rax
    __m128i v4;         // [rsp+20h] [rbp-10h] BYREF
    __m128i v5;         // [rsp+58h] [rbp+28h] BYREF
    unsigned __int8 v6; // [rsp+68h] [rbp+38h] BYREF

    v5.m128i_i8[0] = read<quint8>();
    v2 = v5.m128i_i8[0];
    if (v5.m128i_i8[0] < 0)
    {
        v5.m128i_i8[0] = 0;
        if ((v2 & 0xC0) == 0x80)
        {
            v5.m128i_i8[0] = read<quint8>();
            result = v5.m128i_u8[0] | ((v2 & 0x3F) << 8) | 0xFFFFC000;
            if ((v2 & 0x20) == 0)
                return v5.m128i_u8[0] | ((unsigned __int8)(v2 & 0x3F) << 8);
        }
        else
        {
            v5.m128i_i8[8] = 0;
            if ((v2 & 0xE0) == 0xC0)
            {
                v5.m128i_i8[0] = read<quint8>();
                v5.m128i_i8[8] = read<quint8>();
                result = v5.m128i_u8[8] | ((v5.m128i_u8[0] | ((v2 & 0x1F) << 8)) << 8) | 0xFFE00000;
                if ((v2 & 0x10) == 0)
                    return v5.m128i_u8[8] | ((v5.m128i_u8[0] | ((unsigned __int8)(v2 & 0x1F) << 8)) << 8);
            }
            else
            {
                v6 = 0;
                if ((v2 & 0xF0) == 0xE0)
                {
                    v5.m128i_i8[0] = read<quint8>();
                    v5.m128i_i8[8] = read<quint8>();
                    v6 = read<quint8>();
                    result = v6 | ((v5.m128i_u8[8] | ((v5.m128i_u8[0] | ((v2 & 0xF) << 8)) << 8)) << 8) | 0xF0000000;
                    if ((v2 & 8) == 0)
                        return v6 | ((v5.m128i_u8[8] | ((v5.m128i_u8[0] | ((unsigned __int8)(v2 & 0xF) << 8)) << 8)) << 8);
                }
                else
                {
                    v4.m128i_i8[0] = 0;
                    v5.m128i_i8[0] = read<quint8>();
                    v5.m128i_i8[8] = read<quint8>();
                    v6 = read<quint8>();
                    v4.m128i_i8[0] = read<quint8>();
                    return v4.m128i_u8[0] | ((v6 | ((v5.m128i_u8[8] | (v5.m128i_u8[0] << 8)) << 8)) << 8);
                }
            }
        }
    }
    else
    {
        result = v5.m128i_u8[0] | 0xFFFFFF80;
        if ((v5.m128i_i8[0] & 0x40) == 0)
            return v5.m128i_u8[0];
    }
    return result;
}

void CBuffer::ReadData_2()
{
    qint16 len = read<quint16>();
    read(len);
}

void CBuffer::ReadData_3()
{
    quint16 len = read<quint16>();
    if (len)
    {
        read(len);
    }
}

void CBuffer::ReadData_4()
{
    qint16 size = read<quint16>();
    for (qint16 i = 0; i < size; i++)
    {
        read<quint32>();
    }
}

void CBuffer::Recv_Link2_14b()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x14b, m_socket);

    ReadData();
    quint64 result = ReadData_0();
    quint64 v8 = result;
    if (result)
    {
        do
        {
            ReadData_0();
            ReadData_1();
            --v8;
        } while (v8);
    }
}

void CBuffer::Recv_Link2_1a3()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x1a3, m_socket);

    read<quint8>();
    read<quint8>();
    read<quint8>();
}

void CBuffer::Recv_Link2_142()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x142, m_socket);

    ReadData();
}

void CBuffer::Recv_Link2_14c()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x14c, m_socket);

    ReadData();
    read<quint16>();
    qint64 result = ReadData_0();
    qint64 v8 = result;
    if (result)
    {
        do
        {
            ReadData_0();

            ReadData_1();

            --v8;
        } while (v8);
    }
}

void CBuffer::Recv_Link2_216()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x216, m_socket);

    ReadData();
}

void CBuffer::Recv_Link2_173()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x173, m_socket);

    ReadData();
}

void CBuffer::Recv_Link2_14d()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x14d, m_socket);

    ReadData();
    read<quint8>();
}
void CBuffer::Recv_Link2_149()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x149, m_socket);

    ReadData();
    read<quint32>();
    read<quint32>();
    read<quint8>();
    read<quint16>();
    read<quint8>();
}

void CBuffer::Recv_Link2_274()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x274, m_socket);
}

void CBuffer::Recv_Link2_3b()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x3b, m_socket);

    read<quint32>();
    read(0x13);
}

void CBuffer::Recv_Link1_02()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x2, m_socket);

    ReadData_2();
    ReadData_2();
}

void CBuffer::Recv_Link1_04()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x4, m_socket);

    read<quint16>();
    quint16 ret = read<quint16>();
    int size = 0;
    if (ret)
    {
        size *= 2;
    }
    read(size);
    read(0x20);
    read(0x1);
    readString();
}

void CBuffer::Recv_Link2_0f()
{
    read<quint32>();
}

void CBuffer::Recv_Link1_19()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x19, m_socket);

    read<quint64>();
    //fs_unknown_1() 函数头
    quint32 size = read<quint32>();
    for (quint32 i = 0; i < size; i++)
    {
        quint16 size1 = read<quint16>();
        read(size1 ? size1 * 2 : 0);

        size1 = read<quint16>();
        read(size1 ? size1 * 2 : 0);

        readString();
        readString();
        read<quint64>();
        read<quint64>();
        read<quint64>();
        read<quint16>();
        read<quint8>();
        read<quint8>();
    }
    //fs_unknown_1() 函数尾
}

void CBuffer::Recv_Link1_14()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV手动解析  ID:%x SOCKET:%llx\n", 0x14, m_socket);
}

void CBuffer::Recv_Link1_13()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV脚本解析  ID:%x SOCKET:%llx\n", 0x13, m_socket);

    read<quint32>();
    read<quint32>();
    read<quint32>();
    quint8 size = read<quint8>();
    for (quint8 i = 0; i < size; i++)
    {
        read(0x1c);
    }
    read(0x40);
}

void CBuffer::Recv_Link2_13()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV脚本解析  ID:%x SOCKET:%llx\n", 0x13, m_socket);

    quint16 size = read<quint16>();
    read<quint16>();
    read(size * 2);
    read(size);
}

void CBuffer::Recv_Link1_15()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV脚本解析  ID:%x SOCKET:%llx\n", 0x15, m_socket);
    read<quint16>();
}

void CBuffer::Recv_Link2_15()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV脚本解析  ID:%x SOCKET:%llx\n", 0x15, m_socket);
    read<quint32>();
}

void CBuffer::Recv_Link2_10()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0x6);
    printf("\nRECV脚本解析  ID:%x SOCKET:%llx\n", 0x10, m_socket);

    read<quint16>();
    readString();
    read<quint32>();
    read<quint8>();
    read<quint8>();
    read<quint8>();
    read<quint8>();

    __m128i ret;
    read(&ret, 0X3);
    read<quint8>();
    read<quint8>();
    read<quint8>();

    printf("read:%x\n", ret.m128i_u8[0]);

    if ((ret.m128i_u8[0] & 8) != 0)
    {
        read<quint16>();
    }
    ReadData_4();
    quint16 v6 = read<quint16>();
    if (v6 >= 0)
    {
        //goto LABEL_13;
        for (quint16 i = 0; i < v6; i++)
        {
            read<quint16>();
        }
    }

    v6 = read<quint8>();
    if (v6 > 0)
    {
        //goto LABEL_24;
        for (quint16 i = 0; i < v6; i++)
        {
            read<quint8>();
        }
    }
    if ((ret.m128i_u8[1] & 1) != 0)
    {
        read<quint8>();
        v6 = read<quint8>();
        if (v6 > 0)
        {
            //goto LABEL_36;
            for (quint16 i = 0; i < v6; i++)
            {
                read<quint8>();
            }
        }
    }

    if ((ret.m128i_u8[1] & 2) == 0)
    {
        if (ret.m128i_i8[0] < 0)
        {
            ReadData_0();
        }
    }
}