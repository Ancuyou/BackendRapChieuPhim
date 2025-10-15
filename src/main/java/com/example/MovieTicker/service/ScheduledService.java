package com.example.MovieTicker.service;

import java.time.LocalDateTime;
import java.util.List;

import com.example.MovieTicker.repository.PendingRegistrationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.MovieTicker.entity.HoaDon;
import com.example.MovieTicker.entity.Ve;
import com.example.MovieTicker.enums.InvoiceStatus;
import com.example.MovieTicker.enums.TicketStatus;
import com.example.MovieTicker.repository.HoaDonRepository;

@Service
public class ScheduledService {
    
    private static final Logger logger = LoggerFactory.getLogger(ScheduledService.class);
    
    @Autowired
    private HoaDonRepository hoaDonRepository;
    @Autowired
    private PendingRegistrationRepository pendingRepo;
    
    /**
     * Chạy mỗi 2 phút để kiểm tra và cập nhật hóa đơn hết hạn
     * Hóa đơn hết hạn sau 10 phút không thanh toán
     */
    @Scheduled(fixedRate = 120000) // 2 phút = 120,000ms
    @Transactional
    public void cleanupExpiredInvoices() {
        try {
            LocalDateTime expiredTime = LocalDateTime.now().minusMinutes(10);
            
            // Tìm tất cả hóa đơn PROCESSING đã hết hạn
            List<HoaDon> expiredInvoices = hoaDonRepository.findExpiredProcessingInvoices(expiredTime);
                
            if (!expiredInvoices.isEmpty()) {
                logger.info("Tìm thấy {} hóa đơn hết hạn, đang cập nhật trạng thái...", expiredInvoices.size());
                
                for (HoaDon hoaDon : expiredInvoices) {
                    // Cập nhật trạng thái hóa đơn thành EXPIRED
                    hoaDon.setTrangThai(InvoiceStatus.EXPIRED.getCode());
                    
                    // Cập nhật trạng thái tất cả vé trong hóa đơn thành EXPIRED
                    if (hoaDon.getVes() != null) {
                        for (Ve ve : hoaDon.getVes()) {
                            ve.setTrangThai(TicketStatus.EXPIRED.getCode());
                        }
                    }
                    
                    logger.info("Cập nhật hóa đơn {} thành EXPIRED", hoaDon.getMaHD());
                }
                
                // Lưu tất cả thay đổi
                hoaDonRepository.saveAll(expiredInvoices);
                logger.info("Đã cập nhật {} hóa đơn hết hạn", expiredInvoices.size());
            }
            
        } catch (Exception e) {
            logger.error("Lỗi khi cleanup hóa đơn hết hạn: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Cleanup chi tiết - chạy mỗi 30 phút để kiểm tra và log các hóa đơn cũ
     * Không xóa hóa đơn, chỉ cập nhật trạng thái và log để admin theo dõi
     */
    @Scheduled(fixedRate = 1800000) // 30 phút = 1,800,000ms
    @Transactional
    public void detailedCleanup() {
        try {
            LocalDateTime oldTime = LocalDateTime.now().minusHours(24); // 24 giờ trước
            
            // Tìm các hóa đơn EXPIRED cũ hơn 24 giờ để theo dõi
            List<HoaDon> oldExpiredInvoices = hoaDonRepository.findExpiredInvoicesByStatus(
                InvoiceStatus.EXPIRED.getCode(), oldTime);
            
            if (!oldExpiredInvoices.isEmpty()) {
                logger.info("Tìm thấy {} hóa đơn expired cũ hơn 24 giờ cần theo dõi", 
                    oldExpiredInvoices.size());
                
                // Chỉ log để admin theo dõi, không xóa dữ liệu
                for (HoaDon hoaDon : oldExpiredInvoices) {
                    logger.info("Hóa đơn expired cũ: ID={}, ngày lập={}, tổng tiền={}", 
                        hoaDon.getMaHD(), hoaDon.getNgayLap(), hoaDon.getTongTien());
                }
                
                // Có thể thêm thống kê hoặc gửi report cho admin
                logger.info("Tổng cộng {} hóa đơn expired trong 24h qua", oldExpiredInvoices.size());
            }
            
        } catch (Exception e) {
            logger.error("Lỗi khi detailed cleanup: {}", e.getMessage(), e);
        }
    }

    /**
     * Tác vụ này sẽ chạy mỗi giờ để xóa các yêu cầu đăng ký đã hết hạn.
     * (cron = "giây phút giờ ngày tháng ngày_trong_tuần")
     */
    @Scheduled(cron = "0 0 * * * ?") // Chạy vào đầu mỗi giờ
    @Transactional
    public void cleanupExpiredRegistrations() {
        pendingRepo.deleteByExpiryDateBefore(LocalDateTime.now());
        logger.info("Cleaned up expired pending registrations.");
    }
}