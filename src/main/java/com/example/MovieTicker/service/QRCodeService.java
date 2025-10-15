package com.example.MovieTicker.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

@Service
public class QRCodeService {

    @Value("${qr.code.upload.path:uploads/qr-codes}")
    private String uploadPath;

    @Value("${qr.code.base.url:http://localhost:8080}")
    private String baseUrl;

    /**
     * Tạo QR Code và lưu file ảnh
     * @param data Nội dung QR code (thông tin vé)
     * @param fileName Tên file (mã vé)
     * @return Đường dẫn URL đầy đủ đến file QR code
     */
    public String generateQRCode(String data, String fileName) {
        try {
         
            createDirectoryIfNotExists();

            Map<EncodeHintType, Object> hints = new HashMap<>();
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
            hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");

            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(data, BarcodeFormat.QR_CODE, 300, 300, hints);

           
            BufferedImage qrImage = createQRImage(bitMatrix);

          
            String filename = fileName + ".png";
            Path filePath = Paths.get(uploadPath, filename);
            File outputFile = new File(filePath.toString());
            ImageIO.write(qrImage, "png", outputFile);

            return baseUrl + "/uploads/qr-codes/" + filename;

        } catch (WriterException | IOException e) {
            throw new RuntimeException("Lỗi khi tạo QR code: " + e.getMessage(), e);
        }
    }

   
    private void createDirectoryIfNotExists() throws IOException {
        Path path = Paths.get(uploadPath);
        if (!Files.exists(path)) {
            Files.createDirectories(path);
        }
    }

   
    private BufferedImage createQRImage(BitMatrix bitMatrix) {
        int width = bitMatrix.getWidth();
        int height = bitMatrix.getHeight();
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                image.setRGB(x, y, bitMatrix.get(x, y) ? Color.BLACK.getRGB() : Color.WHITE.getRGB());
            }
        }

        return image;
    }

    /**
     * Tạo nội dung QR code cho vé
     * @param maVe Mã vé
     * @param tenPhim Tên phim
     * @param tenPhongChieu Tên phòng chiếu
     * @param tenGhe Tên ghế
     * @param thoiGianChieu Thời gian chiếu
     * @return Nội dung QR code dạng JSON
     */
    public String createTicketQRContent(String maVe, String tenPhim, String tenPhongChieu,
                                          String tenGhe, String thoiGianChieu, String trangThai) {
        return String.format(
            "{\n" +
            "  \"maVe\": \"%s\",\n" +
            "  \"tenPhim\": \"%s\",\n" +
            "  \"phongChieu\": \"%s\",\n" +
            "  \"ghe\": \"%s\",\n" +
            "  \"thoiGian\": \"%s\",\n" +
            "  \"trangThai\": \"%s\",\n" +
            "  \"type\": \"MovieTicket\"\n" +
            "}",
            maVe, tenPhim, tenPhongChieu, tenGhe, thoiGianChieu, trangThai
        );
    }
}