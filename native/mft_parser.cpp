/**
 * FORENSIX MFT Parser (C++ Native Module)
 * High-performance NTFS Master File Table parser for deleted file recovery.
 * 
 * Compile: g++ -O3 -shared -fPIC -o mft_parser.so mft_parser.cpp
 * Usage:   Python ctypes integration for MFT analysis
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>

// MFT Record structure constants
#define MFT_RECORD_SIZE 1024
#define MFT_MAGIC "FILE"
#define MFT_MAGIC_SIZE 4

// MFT Attribute types
#define ATTR_STANDARD_INFORMATION 0x10
#define ATTR_ATTRIBUTE_LIST       0x20
#define ATTR_FILE_NAME            0x30
#define ATTR_DATA                 0x80

// File flags
#define FILE_FLAG_IN_USE     0x0001
#define FILE_FLAG_DIRECTORY  0x0002
#define FILE_FLAG_DELETED    0x0000

struct MFTRecord {
    uint32_t record_number;
    char magic[5];
    uint16_t sequence_number;
    uint16_t hard_link_count;
    uint16_t first_attr_offset;
    uint16_t flags;
    uint32_t record_size;
    
    // Parsed data
    std::string filename;
    std::string full_path;
    uint64_t file_size;
    uint64_t parent_directory;
    uint64_t creation_time;
    uint64_t modified_time;
    uint64_t access_time;
    uint64_t mft_change_time;
    bool is_deleted;
    bool is_directory;
    
    MFTRecord() : record_number(0), sequence_number(0), 
                  hard_link_count(0), first_attr_offset(0),
                  flags(0), record_size(MFT_RECORD_SIZE),
                  file_size(0), parent_directory(0),
                  creation_time(0), modified_time(0),
                  access_time(0), mft_change_time(0),
                  is_deleted(false), is_directory(false) {
        memset(magic, 0, sizeof(magic));
    }
};

class MFTParser {
private:
    std::ifstream mft_file;
    std::string mft_path;
    std::vector<MFTRecord> records;
    uint64_t total_records;
    bool is_open;

public:
    MFTParser() : total_records(0), is_open(false) {}
    
    ~MFTParser() {
        close();
    }
    
    /**
     * Open MFT file for parsing.
     * @param path Path to $MFT file
     * @return true if successful
     */
    bool open(const std::string& path) {
        mft_path = path;
        mft_file.open(path, std::ios::binary);
        
        if (!mft_file.is_open()) {
            std::cerr << "Error opening MFT: " << path << std::endl;
            return false;
        }
        
        // Get file size
        mft_file.seekg(0, std::ios::end);
        uint64_t file_size = mft_file.tellg();
        mft_file.seekg(0, std::ios::beg);
        
        total_records = file_size / MFT_RECORD_SIZE;
        
        std::cout << "MFT opened: " << path << std::endl;
        std::cout << "  File size: " << file_size << " bytes" << std::endl;
        std::cout << "  Total records: " << total_records << std::endl;
        
        is_open = true;
        return true;
    }
    
    /**
     * Close the MFT file.
     */
    void close() {
        if (mft_file.is_open()) {
            mft_file.close();
        }
        is_open = false;
    }
    
    /**
     * Parse all MFT records.
     * @return Number of records parsed
     */
    int parse_all() {
        if (!is_open) {
            return 0;
        }
        
        records.clear();
        char buffer[MFT_RECORD_SIZE];
        int parsed_count = 0;
        int deleted_count = 0;
        
        for (uint64_t i = 0; i < total_records; i++) {
            mft_file.seekg(i * MFT_RECORD_SIZE);
            mft_file.read(buffer, MFT_RECORD_SIZE);
            
            MFTRecord record;
            if (parse_record(buffer, record)) {
                records.push_back(record);
                parsed_count++;
                
                if (record.is_deleted) {
                    deleted_count++;
                }
                
                if (parsed_count % 10000 == 0) {
                    std::cout << "  Parsed " << parsed_count << " records... ("
                              << deleted_count << " deleted)" << std::endl;
                }
            }
        }
        
        std::cout << "Parsing complete: " << parsed_count << " records ("
                  << deleted_count << " deleted)" << std::endl;
        
        return parsed_count;
    }
    
    /**
     * Parse a single MFT record from buffer.
     */
    bool parse_record(const char* buffer, MFTRecord& record) {
        // Check magic bytes
        if (memcmp(buffer, MFT_MAGIC, MFT_MAGIC_SIZE) != 0) {
            return false;
        }
        
        memcpy(record.magic, buffer, MFT_MAGIC_SIZE);
        record.magic[MFT_MAGIC_SIZE] = '\0';
        
        // Parse fixup array offset (offset 4, 2 bytes)
        uint16_t fixup_offset = *(uint16_t*)(buffer + 4);
        uint16_t fixup_count = *(uint16_t*)(buffer + 6);
        
        // Parse sequence number (offset 16, 2 bytes)
        record.sequence_number = *(uint16_t*)(buffer + 16);
        
        // Parse hard link count (offset 18, 2 bytes)
        record.hard_link_count = *(uint16_t*)(buffer + 18);
        
        // Parse first attribute offset (offset 20, 2 bytes)
        record.first_attr_offset = *(uint16_t*)(buffer + 20);
        
        // Parse flags (offset 22, 2 bytes)
        record.flags = *(uint16_t*)(buffer + 22);
        
        // Determine if deleted or directory
        record.is_deleted = !(record.flags & FILE_FLAG_IN_USE);
        record.is_directory = (record.flags & FILE_FLAG_DIRECTORY);
        
        // Parse record size (offset 24, 4 bytes)
        record.record_size = *(uint32_t*)(buffer + 24);
        
        // Parse attributes
        uint16_t attr_offset = record.first_attr_offset;
        
        while (attr_offset < MFT_RECORD_SIZE) {
            uint32_t attr_type = *(uint32_t*)(buffer + attr_offset);
            uint32_t attr_length = *(uint32_t*)(buffer + attr_offset + 4);
            
            if (attr_length == 0 || attr_type == 0xFFFFFFFF) {
                break;
            }
            
            // Parse Standard Information attribute
            if (attr_type == ATTR_STANDARD_INFORMATION) {
                parse_standard_info(buffer + attr_offset, record);
            }
            
            // Parse File Name attribute
            if (attr_type == ATTR_FILE_NAME) {
                parse_file_name(buffer + attr_offset, record);
            }
            
            attr_offset += attr_length;
            
            // Safety check
            if (attr_offset >= MFT_RECORD_SIZE - 8) {
                break;
            }
        }
        
        record.record_number = records.size();
        
        return true;
    }
    
    /**
     * Parse Standard Information attribute.
     */
    void parse_standard_info(const char* attr_buffer, MFTRecord& record) {
        uint8_t non_resident = attr_buffer[8];
        uint16_t content_offset;
        uint32_t content_size;
        
        if (non_resident == 0) {
            // Resident attribute
            content_offset = *(uint16_t*)(attr_buffer + 20);
            content_size = *(uint32_t*)(attr_buffer + 16);
        } else {
            // Non-resident attribute - skip for now
            return;
        }
        
        const char* content = attr_buffer + content_offset;
        
        if (content_size >= 48) {
            record.creation_time = *(uint64_t*)(content);
            record.modified_time = *(uint64_t*)(content + 8);
            record.mft_change_time = *(uint64_t*)(content + 16);
            record.access_time = *(uint64_t*)(content + 24);
        }
    }
    
    /**
     * Parse File Name attribute.
     */
    void parse_file_name(const char* attr_buffer, MFTRecord& record) {
        uint8_t non_resident = attr_buffer[8];
        uint16_t content_offset;
        uint32_t content_size;
        
        if (non_resident == 0) {
            content_offset = *(uint16_t*)(attr_buffer + 20);
            content_size = *(uint32_t*)(attr_buffer + 16);
        } else {
            return;
        }
        
        const char* content = attr_buffer + content_offset;
        
        // Parent directory reference (offset 0, 6 bytes)
        record.parent_directory = *(uint64_t*)(content) & 0x0000FFFFFFFFFFFF;
        
        // File name length (offset 64, 1 byte)
        uint8_t name_length = content[64];
        
        // File name (offset 66, UTF-16LE)
        if (name_length > 0 && name_length < 256) {
            std::string filename;
            for (int i = 0; i < name_length && (66 + i * 2) < (int)content_size; i++) {
                char16_t ch = *(uint16_t*)(content + 66 + i * 2);
                if (ch >= 32 && ch < 127) {
                    filename += (char)ch;
                }
            }
            record.filename = filename;
        }
        
        // File size (offset 48, 8 bytes)
        record.file_size = *(uint64_t*)(content + 48);
    }
    
    /**
     * Get all parsed records.
     */
    const std::vector<MFTRecord>& get_records() const {
        return records;
    }
    
    /**
     * Get deleted files only.
     */
    std::vector<MFTRecord> get_deleted_files() const {
        std::vector<MFTRecord> deleted;
        for (const auto& rec : records) {
            if (rec.is_deleted && !rec.is_directory) {
                deleted.push_back(rec);
            }
        }
        return deleted;
    }
    
    /**
     * Get files by extension.
     */
    std::vector<MFTRecord> get_files_by_extension(const std::string& ext) const {
        std::vector<MFTRecord> result;
        std::string ext_lower = ext;
        std::transform(ext_lower.begin(), ext_lower.end(), ext_lower.begin(), ::tolower);
        
        for (const auto& rec : records) {
            std::string name = rec.filename;
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            
            if (name.length() >= ext_lower.length() &&
                name.substr(name.length() - ext_lower.length()) == ext_lower) {
                result.push_back(rec);
            }
        }
        return result;
    }
    
    /**
     * Get total record count.
     */
    int get_total_records() const {
        return records.size();
    }
    
    /**
     * Get deleted record count.
     */
    int get_deleted_count() const {
        int count = 0;
        for (const auto& rec : records) {
            if (rec.is_deleted) count++;
        }
        return count;
    }
};

// C-style interface for Python ctypes
extern "C" {
    
    MFTParser* create_parser() {
        return new MFTParser();
    }
    
    void destroy_parser(MFTParser* parser) {
        if (parser) {
            delete parser;
        }
    }
    
    bool open_mft(MFTParser* parser, const char* path) {
        if (!parser) return false;
        return parser->open(std::string(path));
    }
    
    void close_mft(MFTParser* parser) {
        if (parser) {
            parser->close();
        }
    }
    
    int parse_all_records(MFTParser* parser) {
        if (!parser) return 0;
        return parser->parse_all();
    }
    
    int get_total_records(MFTParser* parser) {
        if (!parser) return 0;
        return parser->get_total_records();
    }
    
    int get_deleted_count(MFTParser* parser) {
        if (!parser) return 0;
        return parser->get_deleted_count();
    }
}
