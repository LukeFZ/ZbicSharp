using System.Runtime.CompilerServices;
using static ZstdSharp.UnsafeHelper;

namespace ZstdSharp.Unsafe
{
    public static unsafe partial class Methods
    {
        /*===   Version   ===*/
        private static uint FSE_versionNumber()
        {
            return 0 * 100 * 100 + 9 * 100 + 0;
        }

        /*===   Error Management   ===*/
        private static bool FSE_isError(nuint code)
        {
            return ERR_isError(code);
        }

        private static string FSE_getErrorName(nuint code)
        {
            return ERR_getErrorName(code);
        }

        /* Error Management */
        private static bool HUF_isError(nuint code)
        {
            return ERR_isError(code);
        }

        private static string HUF_getErrorName(nuint code)
        {
            return ERR_getErrorName(code);
        }

        /*-**************************************************************
         *  FSE NCount encoding-decoding
         ****************************************************************/
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static nuint FSE_readNCount_bic(short* normalizedCounter, uint* maxSVPtr, uint* tableLogPtr,
                           void* headerBuffer, nuint hbSize)
        {    
            uint* bicCounter = stackalloc uint[257];
            if (hbSize == 0) 
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));

            byte* ip = (byte*) headerBuffer;
            uint bitStream = *ip;
            nuint rawDataSize = bitStream & 0x7F;     /* Bitstream encodes the segment's raw data size in the first 7 bits. */
            uint useLowProbCount = bitStream >> 7;

            if (rawDataSize >= hbSize) 
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));

            nuint dataSize = rawDataSize + 1;
            if (dataSize >= hbSize) 
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));

            ulong i, l, j, k;
            
            for (i = 0; rawDataSize != 0; i = *(ip + rawDataSize--) | (i << 8)) {
                if (((i >> 32) & 0xFFFFFFFF) >= 0x100) 
                    break;
            }
            
            ulong encodedCharTable = i / 0x34;  
            for (j = i % 0x34; rawDataSize != 0; encodedCharTable = * (ip + rawDataSize--) | (encodedCharTable << 8)) {
                if (((encodedCharTable >> 32) & 0xFFFFFFFF) >= 0x100) 
                    break;
            }

            uint charNum = (uint)(j + 1);
            if (charNum > *maxSVPtr) 
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));

            ulong charTable = encodedCharTable >> 3;
            for (k = encodedCharTable & 0x7; rawDataSize != 0; charTable = *(ip + rawDataSize--) | (charTable << 8))
            {
                if (((charTable >> 32) & 0xFFFFFFFF) >= 0x100) 
                    break;
            }

            int tableLog = (int)(k + 5);
            uint remaining = 1u << tableLog;
            for (l = charTable / remaining; rawDataSize != 0; l = *(ip + rawDataSize--) | (l << 8))
            {
                if (((l >> 32) & 0xFFFFFFFF) >= 0x100) 
                    break;
            }

            /* Find the last entry of the symbol occurrence table. */
            ulong charLast = charTable % remaining + 1;
            if (useLowProbCount != 0) 
                charLast = charNum + charTable % remaining + 2;

            /* Strictly calculate the next power of 2. */
            uint charNumNextPow2 = charNum;
            charNumNextPow2 |= (charNumNextPow2 >> 1);
            charNumNextPow2 |= (charNumNextPow2 >> 2);
            charNumNextPow2 |= (charNumNextPow2 >> 4);
            charNumNextPow2 |= (charNumNextPow2 >> 8);
            charNumNextPow2 |= (charNumNextPow2 >> 16);
            charNumNextPow2++;

            if (charNumNextPow2 > 0xFF) return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
            bicCounter[charNumNextPow2] = (uint)charLast;

            /* Perform interpolative decoding (cumulative).
             * l encodes the symbol occurrence table as an ulong.
             */
            uint bicCount = 0;
            if (charNumNextPow2 != 0xFF)
            {
                do
                {
                    ulong bicTableOffset = 3 * (bicCount - charNumNextPow2 + 0x100);
                    uint btMiddleIndex = BIC_table[bicTableOffset + 0];
                    uint btFirstIndex = BIC_table[bicTableOffset + 1];
                    uint btLastIndex = BIC_table[bicTableOffset + 2];
                    uint bcFirstIndexEntry = bicCounter[btFirstIndex];
                    uint bcLastIndexEntry = bicCounter[btLastIndex];

                    if (bcFirstIndexEntry == bcLastIndexEntry)
                    {
                        /* Indices are the same.
                         * Update our counter array with the entry at the first index
                         * for the length of the sequence imin+1 to imax-1.
                        */
                        uint bicCounterIndex = btFirstIndex + 1;
                        if (bicCounterIndex < btLastIndex)
                        {
                            uint btIndexDist = btLastIndex - bicCounterIndex;
                            while (btIndexDist > 0)
                            {
                                bicCounter[bicCounterIndex++] = bcFirstIndexEntry;
                                --btIndexDist;
                            }
                        }
                    }
                    else
                    {
                        /* Do recursive interpolative decoding.
                         * l is updated by l div (lastIndexEntry - firstIndexEntry + 1).
                         * The entry at the middle index is decoded by l mod (lastIndexEntry - firstIndexEntry + 1) + firstIndexEntry.
                        */
                        ulong lNext = l / (bcLastIndexEntry - bcFirstIndexEntry + 1);
                        ulong lEntry = l % (bcLastIndexEntry - bcFirstIndexEntry + 1);
                        for (l = lNext; rawDataSize != 0; l = *(ip + rawDataSize--) | (l << 8))
                        {
                            if (((l >> 32) & 0xFFFFFFFF) >= 0x100) break;
                        }
                        bicCounter[btMiddleIndex] = (uint)(lEntry + bcFirstIndexEntry);
                    }

                    ++bicCount;
                } while (bicCount < charNumNextPow2);
            }

            if (charNum != 0xFF)
            {
                int accCount = 0;
                uint* bc = &bicCounter[1];
                uint charNumLeft = charNum + 1;
                do
                {
                    short bcCount = *(short*)bc++;
                    short countDist = (short)(bcCount - accCount);
                    short count = (short)(countDist - useLowProbCount);
                    accCount += countDist;
                    *normalizedCounter++ = count;

                    int weightedCount = count;
                    if (count < 0) 
                        weightedCount = -count;

                    remaining -= (uint)weightedCount;
                    --charNumLeft;
                } while (charNumLeft != 0);
            }

            if (remaining != 0) 
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));

            *maxSVPtr = charNum;
            *tableLogPtr = (uint)tableLog;

            if (rawDataSize != 0) 
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));

            return dataSize;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static nuint FSE_readNCount_body(short* normalizedCounter, uint* maxSVPtr, uint* tableLogPtr, void* headerBuffer, nuint hbSize)
        {
            byte* istart = (byte*)headerBuffer;
            byte* iend = istart + hbSize;
            byte* ip = istart;
            int nbBits;
            int remaining;
            int threshold;
            uint bitStream;
            int bitCount;
            uint charnum = 0;
            uint maxSV1 = *maxSVPtr + 1;
            int previous0 = 0;
            if (hbSize < 8)
            {
                sbyte* buffer = stackalloc sbyte[8];
                /* This function only works when hbSize >= 8 */
                memset(buffer, 0, sizeof(sbyte) * 8);
                memcpy(buffer, headerBuffer, (uint)hbSize);
                {
                    nuint countSize = FSE_readNCount(normalizedCounter, maxSVPtr, tableLogPtr, buffer, sizeof(sbyte) * 8);
                    if (FSE_isError(countSize))
                        return countSize;
                    if (countSize > hbSize)
                        return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
                    return countSize;
                }
            }

            assert(hbSize >= 8);
            memset(normalizedCounter, 0, (*maxSVPtr + 1) * sizeof(short));
            bitStream = MEM_readLE32(ip);
            nbBits = (int)((bitStream & 0xF) + 5);
            if (nbBits > 15)
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_tableLog_tooLarge));
            bitStream >>= 4;
            bitCount = 4;
            *tableLogPtr = (uint)nbBits;
            remaining = (1 << nbBits) + 1;
            threshold = 1 << nbBits;
            nbBits++;
            for (; ; )
            {
                if (previous0 != 0)
                {
                    /* Count the number of repeats. Each time the
                     * 2-bit repeat code is 0b11 there is another
                     * repeat.
                     * Avoid UB by setting the high bit to 1.
                     */
                    int repeats = (int)(ZSTD_countTrailingZeros32(~bitStream | 0x80000000) >> 1);
                    while (repeats >= 12)
                    {
                        charnum += 3 * 12;
                        if (ip <= iend - 7)
                        {
                            ip += 3;
                        }
                        else
                        {
                            bitCount -= (int)(8 * (iend - 7 - ip));
                            bitCount &= 31;
                            ip = iend - 4;
                        }

                        bitStream = MEM_readLE32(ip) >> bitCount;
                        repeats = (int)(ZSTD_countTrailingZeros32(~bitStream | 0x80000000) >> 1);
                    }

                    charnum += (uint)(3 * repeats);
                    bitStream >>= 2 * repeats;
                    bitCount += 2 * repeats;
                    assert((bitStream & 3) < 3);
                    charnum += bitStream & 3;
                    bitCount += 2;
                    if (charnum >= maxSV1)
                        break;
                    if (ip <= iend - 7 || ip + (bitCount >> 3) <= iend - 4)
                    {
                        assert(bitCount >> 3 <= 3);
                        ip += bitCount >> 3;
                        bitCount &= 7;
                    }
                    else
                    {
                        bitCount -= (int)(8 * (iend - 4 - ip));
                        bitCount &= 31;
                        ip = iend - 4;
                    }

                    bitStream = MEM_readLE32(ip) >> bitCount;
                }

                {
                    int max = 2 * threshold - 1 - remaining;
                    int count;
                    if ((bitStream & (uint)(threshold - 1)) < (uint)max)
                    {
                        count = (int)(bitStream & (uint)(threshold - 1));
                        bitCount += nbBits - 1;
                    }
                    else
                    {
                        count = (int)(bitStream & (uint)(2 * threshold - 1));
                        if (count >= threshold)
                            count -= max;
                        bitCount += nbBits;
                    }

                    count--;
                    if (count >= 0)
                    {
                        remaining -= count;
                    }
                    else
                    {
                        assert(count == -1);
                        remaining += count;
                    }

                    normalizedCounter[charnum++] = (short)count;
                    previous0 = count == 0 ? 1 : 0;
                    assert(threshold > 1);
                    if (remaining < threshold)
                    {
                        if (remaining <= 1)
                            break;
                        nbBits = (int)(ZSTD_highbit32((uint)remaining) + 1);
                        threshold = 1 << nbBits - 1;
                    }

                    if (charnum >= maxSV1)
                        break;
                    if (ip <= iend - 7 || ip + (bitCount >> 3) <= iend - 4)
                    {
                        ip += bitCount >> 3;
                        bitCount &= 7;
                    }
                    else
                    {
                        bitCount -= (int)(8 * (iend - 4 - ip));
                        bitCount &= 31;
                        ip = iend - 4;
                    }

                    bitStream = MEM_readLE32(ip) >> bitCount;
                }
            }

            if (remaining != 1)
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
            if (charnum > maxSV1)
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_maxSymbolValue_tooSmall));
            if (bitCount > 32)
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
            *maxSVPtr = charnum - 1;
            ip += bitCount + 7 >> 3;
            return (nuint)(ip - istart);
        }

        /* Avoids the FORCE_INLINE of the _body() function. */
        private static nuint FSE_readNCount_body_default(short* normalizedCounter, uint* maxSVPtr, uint* tableLogPtr, void* headerBuffer, nuint hbSize)
        {
            // ZBIC Change: use BIC method here
            return FSE_readNCount_bic(normalizedCounter, maxSVPtr, tableLogPtr, headerBuffer, hbSize);
        }

        /*! FSE_readNCount_bmi2():
         * Same as FSE_readNCount() but pass bmi2=1 when your CPU supports BMI2 and 0 otherwise.
         */
        private static nuint FSE_readNCount_bmi2(short* normalizedCounter, uint* maxSVPtr, uint* tableLogPtr, void* headerBuffer, nuint hbSize, int bmi2)
        {
            return FSE_readNCount_body_default(normalizedCounter, maxSVPtr, tableLogPtr, headerBuffer, hbSize);
        }

        /*! FSE_readNCount():
        Read compactly saved 'normalizedCounter' from 'rBuffer'.
        @return : size read from 'rBuffer',
        or an errorCode, which can be tested using FSE_isError().
        maxSymbolValuePtr[0] and tableLogPtr[0] will also be updated with their respective values */
        private static nuint FSE_readNCount(short* normalizedCounter, uint* maxSVPtr, uint* tableLogPtr, void* headerBuffer, nuint hbSize)
        {
            return FSE_readNCount_bmi2(normalizedCounter, maxSVPtr, tableLogPtr, headerBuffer, hbSize, 0);
        }

        /*! HUF_readStats() :
        Read compact Huffman tree, saved by HUF_writeCTable().
        `huffWeight` is destination buffer.
        `rankStats` is assumed to be a table of at least HUF_TABLELOG_MAX U32.
        @return : size read from `src` , or an error Code .
        Note : Needed by HUF_readCTable() and HUF_readDTableX?() .
         */
        private static nuint HUF_readStats(byte* huffWeight, nuint hwSize, uint* rankStats, uint* nbSymbolsPtr, uint* tableLogPtr, void* src, nuint srcSize)
        {
            uint* wksp = stackalloc uint[219];
            return HUF_readStats_wksp(huffWeight, hwSize, rankStats, nbSymbolsPtr, tableLogPtr, src, srcSize, wksp, sizeof(uint) * 219, 0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static nuint HUF_readStats_body(byte* huffWeight, nuint hwSize, uint* rankStats, uint* nbSymbolsPtr, uint* tableLogPtr, void* src, nuint srcSize, void* workSpace, nuint wkspSize, int bmi2)
        {
            uint weightTotal;
            byte* ip = (byte*)src;
            nuint iSize;
            nuint oSize;
            if (srcSize == 0)
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_srcSize_wrong));
            iSize = ip[0];
            if (iSize >= 128)
            {
                oSize = iSize - 127;
                iSize = (oSize + 1) / 2;
                if (iSize + 1 > srcSize)
                    return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_srcSize_wrong));
                if (oSize >= hwSize)
                    return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
                ip += 1;
                {
                    uint n;
                    for (n = 0; n < oSize; n += 2)
                    {
                        huffWeight[n] = (byte)(ip[n / 2] >> 4);
                        huffWeight[n + 1] = (byte)(ip[n / 2] & 15);
                    }
                }
            }
            else
            {
                if (iSize + 1 > srcSize)
                    return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_srcSize_wrong));
                oSize = FSE_decompress_wksp_bmi2(huffWeight, hwSize - 1, ip + 1, iSize, 6, workSpace, wkspSize, bmi2);
                if (FSE_isError(oSize))
                    return oSize;
            }

            memset(rankStats, 0, (12 + 1) * sizeof(uint));
            weightTotal = 0;
            {
                uint n;
                for (n = 0; n < oSize; n++)
                {
                    if (huffWeight[n] > 12)
                        return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
                    rankStats[huffWeight[n]]++;
                    weightTotal += (uint)(1 << huffWeight[n] >> 1);
                }
            }

            if (weightTotal == 0)
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
            {
                uint tableLog = ZSTD_highbit32(weightTotal) + 1;
                if (tableLog > 12)
                    return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
                *tableLogPtr = tableLog;
                {
                    uint total = (uint)(1 << (int)tableLog);
                    uint rest = total - weightTotal;
                    uint verif = (uint)(1 << (int)ZSTD_highbit32(rest));
                    uint lastWeight = ZSTD_highbit32(rest) + 1;
                    if (verif != rest)
                        return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
                    huffWeight[oSize] = (byte)lastWeight;
                    rankStats[lastWeight]++;
                }
            }

            if (rankStats[1] < 2 || (rankStats[1] & 1) != 0)
                return unchecked((nuint)(-(int)ZSTD_ErrorCode.ZSTD_error_corruption_detected));
            *nbSymbolsPtr = (uint)(oSize + 1);
            return iSize + 1;
        }

        /* Avoids the FORCE_INLINE of the _body() function. */
        private static nuint HUF_readStats_body_default(byte* huffWeight, nuint hwSize, uint* rankStats, uint* nbSymbolsPtr, uint* tableLogPtr, void* src, nuint srcSize, void* workSpace, nuint wkspSize)
        {
            return HUF_readStats_body(huffWeight, hwSize, rankStats, nbSymbolsPtr, tableLogPtr, src, srcSize, workSpace, wkspSize, 0);
        }

        private static nuint HUF_readStats_wksp(byte* huffWeight, nuint hwSize, uint* rankStats, uint* nbSymbolsPtr, uint* tableLogPtr, void* src, nuint srcSize, void* workSpace, nuint wkspSize, int flags)
        {
            return HUF_readStats_body_default(huffWeight, hwSize, rankStats, nbSymbolsPtr, tableLogPtr, src, srcSize, workSpace, wkspSize);
        }
    }
}