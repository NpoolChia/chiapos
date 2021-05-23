// Copyright 2018 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SRC_CPP_UNIFORMSORT_HPP_
#define SRC_CPP_UNIFORMSORT_HPP_

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <stdlib.h>

#include "./disk.hpp"
#include "./util.hpp"

namespace UniformSort {

    inline int64_t const BUF_SIZE = 262144;
    const uint8_t zero_pattern[8 * 1024 * 1024] = {0};

    inline static bool IsPositionEmpty(const uint8_t *memory, uint32_t const entry_len)
    {
#if 0
        if (entry_len < sizeof(zero_pattern) / sizeof(zero_pattern[0])) {
            return 0 == memcmp(memory, zero_pattern, entry_len);
        }

        for (uint32_t i = 0; i < entry_len; i++)
            if (memory[i] != 0)
                return false;
#else
        uint32_t i = 0;
        uint32_t j = 0;

        for (i = sizeof(uint32_t), j = 0; i < entry_len; i += sizeof(uint32_t), j += sizeof(uint32_t))
            if (*(uint32_t *)(&memory[j]) != 0)
                return false;

        for (; j < entry_len; j++)
            if (memory[j] != 0)
                return false;
#endif

        return true;
    }

    inline void SortToMemory(
        FileDisk &input_disk,
        uint64_t const input_disk_begin,
        uint8_t *const memory,
        uint32_t const entry_len,
        uint64_t const num_entries,
        uint32_t const bits_begin)
    {
        uint64_t const memory_len = Util::RoundSize(num_entries) * entry_len;
        auto const swap_space = std::make_unique<uint8_t[]>(entry_len);
        auto const buffer = std::make_unique<uint8_t[]>(BUF_SIZE);
        uint64_t bucket_length = 0;
        // The number of buckets needed (the smallest power of 2 greater than 2 * num_entries).

        int loops = entry_len / sizeof(uint32_t);
        int remains = entry_len % sizeof(uint32_t);
        int offset = loops * sizeof(uint32_t);

#if 0
        while ((1ULL << bucket_length) < 2 * num_entries) bucket_length++;
        std::cout << "Bucket length by shift " << bucket_length << " entries " << num_entries << std::endl;
#else
        uint64_t pow2_entries = 2 * num_entries - 1;
        pow2_entries |= pow2_entries >> 1;
        pow2_entries |= pow2_entries >> 2;
        pow2_entries |= pow2_entries >> 4;
        pow2_entries |= pow2_entries >> 8;
        pow2_entries |= pow2_entries >> 16;
        pow2_entries |= pow2_entries >> 32;
        pow2_entries = pow2_entries + 1;

        float fx = (float)pow2_entries;
        unsigned long ix = *(unsigned long *)&fx;
        unsigned long exp = (ix >> 23) & 0xff;

        bucket_length = exp - 127;
#endif

        memset(memory, 0, memory_len);

        uint64_t read_pos = input_disk_begin;
        uint64_t buf_size = 0;
        uint64_t buf_ptr = 0;
        for (uint64_t i = 0; i < num_entries; i++) {
            if (buf_size == 0) {
                // If read buffer is empty, read from disk and refill it.
                buf_size = std::min((uint64_t)BUF_SIZE / entry_len, num_entries - i);
                buf_ptr = 0;
                input_disk.Read(read_pos, buffer.get(), buf_size * entry_len);
                read_pos += buf_size * entry_len;
            }
            buf_size--;
            // First unique bits in the entry give the expected position of it in the sorted array.
            // We take 'bucket_length' bits starting with the first unique one.
            uint64_t pos =
                Util::ExtractNum(buffer.get() + buf_ptr, entry_len, bits_begin, bucket_length) *
                entry_len;

            // As long as position is occupied by a previous entry...
            while (!IsPositionEmpty(memory + pos, entry_len) && pos < memory_len) {
                // ...store there the minimum between the two and continue to push the higher one.
                if (Util::MemCmpBits(
                        memory + pos, buffer.get() + buf_ptr, entry_len, bits_begin) > 0) {
#if 0
                    memcpy(swap_space.get(), memory + pos, entry_len);
                    memcpy(memory + pos, buffer.get() + buf_ptr, entry_len);
                    memcpy(buffer.get() + buf_ptr, swap_space.get(), entry_len);
#else
                    for (uint32_t i = 0, l_offset = 0; i < loops; i++, l_offset += sizeof(uint32_t)) {
                        uint32_t src = *(uint32_t *)(memory + pos + l_offset);
                        src ^= *(uint32_t *)(buffer.get() + buf_ptr + l_offset);
                        *(uint32_t *)(buffer.get() + buf_ptr + l_offset) ^= src;
                        src ^= *(uint32_t *)(buffer.get() + buf_ptr + l_offset);
                        *(uint32_t *)(memory + pos + l_offset) = src;
                    }
                    for (int i = offset; i < remains; i++) {
                        uint8_t src = *(uint8_t *)(memory + pos + i);
                        src ^= *(uint8_t *)(buffer.get() + buf_ptr + i);
                        *(uint8_t *)(buffer.get() + buf_ptr + i) ^= src;
                        src ^= *(uint8_t *)(buffer.get() + buf_ptr + i);
                        *(uint8_t *)(memory + pos + i) = src;
                    }
#endif
                }
                pos += entry_len;
            }
            // Push the entry in the first free spot.
            memcpy(memory + pos, buffer.get() + buf_ptr, entry_len);
            buf_ptr += entry_len;
        }
        uint64_t entries_written = 0;
        // Search the memory buffer for occupied entries.
        for (uint64_t pos = 0; entries_written < num_entries && pos < memory_len;
             pos += entry_len) {
            if (!IsPositionEmpty(memory + pos, entry_len)) {
                // We've found an entry.
                // write the stored entry itself.
                memcpy(
                    memory + entries_written * entry_len,
                    memory + pos,
                    entry_len);
                entries_written++;
            }
        }

        assert(entries_written == num_entries);
    }

    inline void SortToMemoryV2(
        FileDisk &input_disk,
        uint64_t const input_disk_begin,
        uint8_t *const memory,
        uint32_t const entry_len,
        uint64_t const num_entries,
        uint32_t const bits_begin)
    {
        uint64_t const memory_len = Util::RoundSize(num_entries) * entry_len;
        auto const swap_space = std::make_unique<uint8_t[]>(entry_len);
        auto const buffer = std::make_unique<uint8_t[]>(BUF_SIZE);
        uint64_t bucket_length = 0;
        // The number of buckets needed (the smallest power of 2 greater than 2 * num_entries).

        int loops = entry_len / sizeof(uint32_t);
        int remains = entry_len % sizeof(uint32_t);
        int offset = loops * sizeof(uint32_t);

        uint64_t pow2_entries = 2 * num_entries - 1;
        pow2_entries |= pow2_entries >> 1;
        pow2_entries |= pow2_entries >> 2;
        pow2_entries |= pow2_entries >> 4;
        pow2_entries |= pow2_entries >> 8;
        pow2_entries |= pow2_entries >> 16;
        pow2_entries |= pow2_entries >> 32;
        pow2_entries = pow2_entries + 1;

        float fx = (float)pow2_entries;
        unsigned long ix = *(unsigned long *)&fx;
        unsigned long exp = (ix >> 23) & 0xff;

        bucket_length = exp - 127;

        memset(memory, 0, memory_len);
        uint8_t *my_memory = (uint8_t *)malloc(memory_len);
        memset(my_memory, 0, memory_len);
        std::map<uint64_t, std::vector<uint8_t *>, std::greater<uint64_t>> pos_entry_map;

        uint64_t read_pos = input_disk_begin;
        uint64_t buf_size = 0;
        uint64_t buf_ptr = 0;
        for (uint64_t i = 0; i < num_entries; i++) {
            if (buf_size == 0) {
                // If read buffer is empty, read from disk and refill it.
                buf_size = std::min((uint64_t)BUF_SIZE / entry_len, num_entries - i);
                buf_ptr = 0;
                input_disk.Read(read_pos, buffer.get(), buf_size * entry_len);
                read_pos += buf_size * entry_len;
            }
            buf_size--;
            // First unique bits in the entry give the expected position of it in the sorted array.
            // We take 'bucket_length' bits starting with the first unique one.
            uint64_t pos =
                Util::ExtractNum(buffer.get() + buf_ptr, entry_len, bits_begin, bucket_length) *
                entry_len;

            std::vector<uint8_t *> pos_entry_vec;
            if (pos_entry_map.end() == pos_entry_map.find(pos)) {
                pos_entry_map.insert(std::map<uint64_t, std::vector<uint8_t *>>::value_type(pos, pos_entry_vec));
            }

            // As long as position is occupied by a previous entry...
            while (!IsPositionEmpty(my_memory + pos, entry_len) && pos < memory_len) {
                pos += entry_len;
            }
            // Push the entry in the first free spot.
            memcpy(my_memory + pos, buffer.get() + buf_ptr, entry_len);

            std::vector<uint8_t *>::iterator it;
            std::vector<uint8_t *> entry_vec = pos_entry_map[pos];

            bool inserted = false;
            for (int i = 0; i < entry_vec.size(); i++) {
                if (Util::MemCmpBits(
                        my_memory + pos, entry_vec[i], entry_len, bits_begin) > 0) {
                    continue;
                }
                inserted = true;
                entry_vec.insert(entry_vec.begin() + i, my_memory + pos);
                break;
            }

            if (!inserted) {
                entry_vec.push_back(my_memory + pos);
            }

            buf_ptr += entry_len;
        }

        std::map<uint64_t, std::vector<uint8_t *>>::iterator it;
        for (it = pos_entry_map.begin(); it != pos_entry_map.end(); ++it) {
            
        }

        uint64_t entries_written = 0;
        // Search the memory buffer for occupied entries.
        for (uint64_t pos = 0; entries_written < num_entries && pos < memory_len;
             pos += entry_len) {
            if (!IsPositionEmpty(memory + pos, entry_len)) {
                // We've found an entry.
                // write the stored entry itself.
                memcpy(
                    memory + entries_written * entry_len,
                    memory + pos,
                    entry_len);
                entries_written++;
            }
        }

        assert(entries_written == num_entries);
    }
}

#endif  // SRC_CPP_UNIFORMSORT_HPP_
