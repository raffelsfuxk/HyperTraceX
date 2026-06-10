/**
 * FORENSIX Raw Disk Reader (C++ Native Module)
 * High-performance raw disk sector reader for forensic imaging.
 * 
 * Compile: g++ -O3 -shared -fPIC -o raw_reader.so raw_reader.cpp
 * Usage:   Python ctypes integration for ultra-fast disk access
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define SECTOR_SIZE 512
#define DEFAULT_BUFFER_SIZE (1024 * 1024 * 4)  // 4MB buffer

class RawDiskReader {
private:
    int fd;
    std::string device_path;
    uint64_t total_sectors;
    uint64_t current_offset;
    bool is_open;
    char* buffer;
    size_t buffer_size;

public:
    RawDiskReader() : fd(-1), total_sectors(0), current_offset(0), 
                      is_open(false), buffer(nullptr), buffer_size(DEFAULT_BUFFER_SIZE) {
        buffer = new char[buffer_size];
    }
    
    ~RawDiskReader() {
        close_device();
        if (buffer) {
            delete[] buffer;
            buffer = nullptr;
        }
    }
    
    /**
     * Open disk device for raw reading.
     * @param device Device path (e.g., /dev/sda)
     * @return true if successful
     */
    bool open_device(const std::string& device) {
        device_path = device;
        
        // Open device in read-only mode
        fd = open(device.c_str(), O_RDONLY);
        if (fd < 0) {
            std::cerr << "Error opening device: " << device 
                      << " - " << strerror(errno) << std::endl;
            return false;
        }
        
        // Get device size
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (S_ISBLK(st.st_mode)) {
                // Block device - use ioctl to get size
                #ifdef BLKGETSIZE64
                uint64_t size;
                if (ioctl(fd, BLKGETSIZE64, &size) == 0) {
                    total_sectors = size / SECTOR_SIZE;
                }
                #endif
            } else {
                // Regular file
                total_sectors = st.st_size / SECTOR_SIZE;
            }
        }
        
        is_open = true;
        current_offset = 0;
        
        std::cout << "Device opened: " << device << std::endl;
        std::cout << "  Total sectors: " << total_sectors << std::endl;
        std::cout << "  Total size: " << (total_sectors * SECTOR_SIZE / (1024.0 * 1024.0 * 1024.0)) << " GB" << std::endl;
        
        return true;
    }
    
    /**
     * Close the device.
     */
    void close_device() {
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        is_open = false;
    }
    
    /**
     * Read sectors from current position.
     * @param num_sectors Number of sectors to read
     * @param output_buffer Output buffer (must be pre-allocated)
     * @return Number of sectors actually read
     */
    uint64_t read_sectors(uint64_t num_sectors, char* output_buffer) {
        if (!is_open || fd < 0) {
            return 0;
        }
        
        uint64_t bytes_to_read = num_sectors * SECTOR_SIZE;
        uint64_t bytes_read = 0;
        
        while (bytes_read < bytes_to_read) {
            ssize_t result = read(fd, output_buffer + bytes_read, 
                                 bytes_to_read - bytes_read);
            
            if (result < 0) {
                std::cerr << "Read error at offset " << current_offset 
                          << ": " << strerror(errno) << std::endl;
                break;
            }
            
            if (result == 0) {
                // End of device
                break;
            }
            
            bytes_read += result;
            current_offset += result;
        }
        
        return bytes_read / SECTOR_SIZE;
    }
    
    /**
     * Seek to specific sector.
     * @param sector Sector number
     * @return true if successful
     */
    bool seek_to_sector(uint64_t sector) {
        if (!is_open || fd < 0) {
            return false;
        }
        
        off_t offset = sector * SECTOR_SIZE;
        off_t result = lseek(fd, offset, SEEK_SET);
        
        if (result == (off_t)-1) {
            std::cerr << "Seek error: " << strerror(errno) << std::endl;
            return false;
        }
        
        current_offset = offset;
        return true;
    }
    
    /**
     * Read a single sector.
     * @param sector Sector number
     * @param output_buffer Output buffer (must be at least SECTOR_SIZE)
     * @return true if successful
     */
    bool read_single_sector(uint64_t sector, char* output_buffer) {
        if (!seek_to_sector(sector)) {
            return false;
        }
        
        ssize_t result = read(fd, output_buffer, SECTOR_SIZE);
        return (result == SECTOR_SIZE);
    }
    
    /**
     * Get device information.
     */
    std::string get_device_info() {
        std::string info = "Device: " + device_path + "\n";
        info += "Total Sectors: " + std::to_string(total_sectors) + "\n";
        info += "Total Size: " + std::to_string(total_sectors * SECTOR_SIZE) + " bytes\n";
        info += "Sector Size: " + std::to_string(SECTOR_SIZE) + " bytes\n";
        info += "Is Open: " + std::string(is_open ? "Yes" : "No") + "\n";
        return info;
    }
    
    /**
     * Get total sector count.
     */
    uint64_t get_total_sectors() const {
        return total_sectors;
    }
    
    /**
     * Get current position.
     */
    uint64_t get_current_offset() const {
        return current_offset;
    }
    
    /**
     * Check if device is open.
     */
    bool device_is_open() const {
        return is_open;
    }
};

// C-style interface for Python ctypes
extern "C" {
    
    RawDiskReader* create_reader() {
        return new RawDiskReader();
    }
    
    void destroy_reader(RawDiskReader* reader) {
        if (reader) {
            delete reader;
        }
    }
    
    bool open_device(RawDiskReader* reader, const char* device) {
        if (!reader) return false;
        return reader->open_device(std::string(device));
    }
    
    void close_device(RawDiskReader* reader) {
        if (reader) {
            reader->close_device();
        }
    }
    
    uint64_t get_total_sectors(RawDiskReader* reader) {
        if (!reader) return 0;
        return reader->get_total_sectors();
    }
    
    bool seek_to_sector(RawDiskReader* reader, uint64_t sector) {
        if (!reader) return false;
        return reader->seek_to_sector(sector);
    }
    
    uint64_t read_sectors(RawDiskReader* reader, uint64_t num_sectors, char* buffer) {
        if (!reader) return 0;
        return reader->read_sectors(num_sectors, buffer);
    }
    
    bool read_single_sector(RawDiskReader* reader, uint64_t sector, char* buffer) {
        if (!reader) return false;
        return reader->read_single_sector(sector, buffer);
    }
    
    uint64_t get_current_offset(RawDiskReader* reader) {
        if (!reader) return 0;
        return reader->get_current_offset();
    }
    
    bool device_is_open(RawDiskReader* reader) {
        if (!reader) return false;
        return reader->device_is_open();
    }
}

// Test main function
#ifdef STANDALONE_TEST
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <device>" << std::endl;
        return 1;
    }
    
    RawDiskReader reader;
    
    if (!reader.open_device(argv[1])) {
        return 1;
    }
    
    std::cout << reader.get_device_info() << std::endl;
    
    // Read first sector
    char sector[SECTOR_SIZE];
    if (reader.read_single_sector(0, sector)) {
        std::cout << "First sector read successfully" << std::endl;
        
        // Print first 64 bytes as hex
        std::cout << "First 64 bytes: ";
        for (int i = 0; i < 64 && i < SECTOR_SIZE; i++) {
            printf("%02X ", (unsigned char)sector[i]);
            if ((i + 1) % 16 == 0) std::cout << std::endl << "                ";
        }
        std::cout << std::endl;
    }
    
    reader.close_device();
    return 0;
}
#endif
