package com.example.MovieTicker.service;

import com.example.MovieTicker.entity.PasswordResetToken;
import com.example.MovieTicker.response.HoaDonResponse;
import com.example.MovieTicker.response.VeResponse;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import java.io.*;
import java.net.*;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender mailSender;
    @Value("${frontend.base-url}")
    private String frontendBaseUrl;

    public void sendPasswordResetEmail(String to, PasswordResetToken token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Yêu Cầu Đặt Lại Mật Khẩu");
        String resetUrl = frontendBaseUrl + "/reset-password?token=" + token.getToken();
        String emailBody = "Chào bạn,\n\n"
                + "Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn.\n"
                + "Vui lòng nhấp vào đường link dưới đây để đặt lại mật khẩu:\n"
                + resetUrl + "\n\n"
                + "Nếu bạn không yêu cầu việc này, vui lòng bỏ qua email này.\n\n"
                + "Trân trọng,\n"
                + "Đội ngũ Cinema.";
        message.setText(emailBody);
        mailSender.send(message);
    }

    public void sendOtpEmail(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Xác Thực Tài Khoản Cinema");
        String emailBody = "Chào bạn,\n\n"
                + "Cảm ơn bạn đã đăng ký tài khoản tại Cinema.\n"
                + "Mã OTP của bạn là: " + otp + "\n\n"
                + "Mã này sẽ hết hạn sau 5 phút.\n\n"
                + "Trân trọng,\n"
                + "Đội ngũ Cinema.";
        message.setText(emailBody);
        mailSender.send(message);
    }

    public void sendSuccessInvoiceEmail(String to, HoaDonResponse invoiceDetails) throws Exception {
        try {
            System.out.println("=== BẮT ĐẦU GỬI EMAIL ===");
            System.out.println("To: " + to);
            System.out.println("Invoice: " + invoiceDetails.getMaHD());

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_RELATED, "UTF-8");

            helper.setTo(to);
            helper.setSubject("Hóa Đơn Mua Vé");
            helper.setFrom("noreply@cinema.com");

            StringBuilder html = new StringBuilder();
            html.append("<!DOCTYPE html>");
            html.append("<html>");
            html.append("<head><meta charset='UTF-8'></head>");
            html.append("<body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>");
            html.append("<div style='max-width: 600px; margin: 0 auto; padding: 20px;'>");

            html.append("<h3 style='color: #2c3e50;'>Chào bạn,</h3>");
            html.append("<p>Cảm ơn bạn đã mua vé tại Cinema. Dưới đây là chi tiết hóa đơn của bạn:</p>");

            html.append("<div style='background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;'>");
            html.append("<ul style='list-style: none; padding: 0;'>");
            html.append("<li style='margin: 10px 0;'><b>Mã hóa đơn:</b> ").append(invoiceDetails.getMaHD()).append("</li>");
            html.append("<li style='margin: 10px 0;'><b>Ngày lập:</b> ").append(invoiceDetails.getNgayLap()).append("</li>");
            html.append("<li style='margin: 10px 0;'><b>Tổng tiền:</b> ").append(invoiceDetails.getTongTien()).append(" VNĐ</li>");
            html.append("<li style='margin: 10px 0;'><b>Phương thức thanh toán:</b> ").append(invoiceDetails.getPhuongThucThanhToan()).append("</li>");
            html.append("</ul>");
            html.append("</div>");

            // Thông tin vé
            if (invoiceDetails.getDanhSachVe() != null && !invoiceDetails.getDanhSachVe().isEmpty()) {
                System.out.println("Số lượng vé: " + invoiceDetails.getDanhSachVe().size());
                html.append("<h4 style='color: #2c3e50; margin-top: 30px;'>Thông tin vé:</h4>");

                int qrIndex = 0;
                for (VeResponse ve : invoiceDetails.getDanhSachVe()) {
                    System.out.println("Xử lý vé: " + ve.getMaVe());

                    html.append("<div style='border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; background: white;'>");
                    html.append("<p style='margin: 5px 0;'><b>Mã vé:</b> ").append(ve.getMaVe()).append("</p>");
                    html.append("<p style='margin: 5px 0;'><b>Tên phim:</b> ").append(ve.getTenPhim()).append("</p>");
                    html.append("<p style='margin: 5px 0;'><b>Ghế:</b> ").append(ve.getTenGhe()).append("</p>");
                    html.append("<p style='margin: 5px 0;'><b>Thời gian chiếu:</b> ").append(ve.getThoiGianChieu()).append("</p>");

                    // Nhúng QR code
                    if (ve.getQrCodeUrl() != null && !ve.getQrCodeUrl().isEmpty()) {
                        String contentId = "qrcode" + qrIndex;
                        html.append("<div style='margin-top: 15px; text-align: center;'>");
                        html.append("<p style='margin: 10px 0; font-weight: bold;'>Mã QR của bạn:</p>");
                        html.append("<img src='cid:").append(contentId).append("' alt='QR Code' style='width:200px; height:200px; border: 2px solid #ddd; padding: 10px; background: white;'/>");
                        html.append("</div>");

                        // Đính kèm ảnh QR code
                        attachQRCodeImage(helper, ve.getQrCodeUrl(), contentId, ve.getMaVe());
                        qrIndex++;
                    } else {
                        System.out.println("WARNING - QR Code URL is null or empty for ticket: " + ve.getMaVe());
                        html.append("<p style='color: red; margin-top: 15px;'>Mã QR không khả dụng. Vui lòng liên hệ hỗ trợ.</p>");
                    }
                    html.append("</div>");
                }
            } else {
                System.out.println("WARNING - Danh sách vé rỗng hoặc null");
                html.append("<p style='color: red;'>Không có thông tin vé. Vui lòng liên hệ hỗ trợ.</p>");
            }

            html.append("<p style='margin-top: 30px;'>Chúng tôi hy vọng bạn sẽ có những trải nghiệm tuyệt vời tại rạp chiếu phim của chúng tôi.</p>");
            html.append("<p style='color: #666; margin-top: 20px;'>Trân trọng,<br><b>Đội ngũ Cinema</b></p>");

            html.append("</div>");
            html.append("</body>");
            html.append("</html>");

            helper.setText(html.toString(), true);

            System.out.println("Đang gửi email...");
            System.out.println("HTML length: " + html.length());
            mailSender.send(message);
            System.out.println("=== GỬI EMAIL THÀNH CÔNG ===");
        } catch (Exception e) {
            System.err.println("=== LỖI GỬI EMAIL ===");
            System.err.println("Lỗi gửi email hóa đơn: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Không thể gửi email hóa đơn: " + invoiceDetails.getMaHD(), e);
        }
    }

    private void attachQRCodeImage(MimeMessageHelper helper, String qrCodeUrl, String contentId, String maVe) throws Exception {
        try {
            if (qrCodeUrl == null || qrCodeUrl.trim().isEmpty()) {
                throw new IllegalArgumentException("QR Code URL is null or empty for ticket: " + maVe);
            }

            System.out.println("DEBUG - QR Code URL: " + qrCodeUrl);
            System.out.println("DEBUG - Content ID: " + contentId);

            String filePath = null;

            if (qrCodeUrl.contains("/uploads/qr-codes/")) {
                int startIndex = qrCodeUrl.indexOf("/uploads/qr-codes/");
                filePath = qrCodeUrl.substring(startIndex + 1); // Bỏ dấu "/" đầu
                System.out.println("DEBUG - Extracted file path: " + filePath);
            } else if (qrCodeUrl.startsWith("http")) {
                System.out.println("DEBUG - Downloading from URL...");
                URL url = new URL(qrCodeUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(15000); // Tăng timeout lên 15 giây
                connection.setReadTimeout(15000);
                connection.setRequestMethod("GET");
                connection.setRequestProperty("User-Agent", "Mozilla/5.0");

                int responseCode = connection.getResponseCode();
                System.out.println("DEBUG - Response code: " + responseCode);

                if (responseCode == 200) {
                    InputStream inputStream = connection.getInputStream();
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }

                    byte[] imageBytes = outputStream.toByteArray();
                    System.out.println("DEBUG - Downloaded bytes: " + imageBytes.length);

                    if (imageBytes.length > 0) {
                        ByteArrayResource resource = new ByteArrayResource(imageBytes);
                        helper.addInline(contentId, resource, "image/png");
                        System.out.println("SUCCESS - Attached from URL for ticket: " + maVe);
                        inputStream.close();
                        return;
                    }
                    inputStream.close();
                    throw new IOException("Downloaded image is empty for ticket: " + maVe);
                } else {
                    throw new IOException("Failed to download QR code from URL, response code: " + responseCode);
                }
            } else if (qrCodeUrl.startsWith("data:image")) {
                System.out.println("DEBUG - Processing Base64...");
                String base64Data = qrCodeUrl.substring(qrCodeUrl.indexOf(",") + 1);
                byte[] imageBytes;
                try {
                    imageBytes = Base64.getDecoder().decode(base64Data);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Invalid Base64 data for ticket: " + maVe, e);
                }
                System.out.println("DEBUG - Decoded bytes: " + imageBytes.length);

                if (imageBytes.length > 0) {
                    ByteArrayResource resource = new ByteArrayResource(imageBytes);
                    helper.addInline(contentId, resource, "image/png");
                    System.out.println("SUCCESS - Attached Base64 for ticket: " + maVe);
                    return;
                }
                throw new IOException("Base64 image is empty for ticket: " + maVe);
            } else {
                filePath = qrCodeUrl;
            }

            if (filePath != null) {
                File qrFile = new File(filePath);
                System.out.println("DEBUG - Trying file path: " + qrFile.getAbsolutePath());
                System.out.println("DEBUG - File exists: " + qrFile.exists());
                System.out.println("DEBUG - File readable: " + qrFile.canRead());
                System.out.println("DEBUG - File size: " + (qrFile.exists() ? qrFile.length() : "N/A"));

                if (qrFile.exists() && qrFile.canRead() && qrFile.length() > 0) {
                    helper.addInline(contentId, qrFile);
                    System.out.println("SUCCESS - Attached local file: " + qrFile.getAbsolutePath() + " for ticket: " + maVe);
                } else {
                    throw new IOException("File not found, not readable, or empty: " + qrFile.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            System.err.println("ERROR - Lỗi đính kèm QR code cho vé: " + maVe + " - " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Không thể đính kèm mã QR cho vé: " + maVe, e);
        }
    }
}