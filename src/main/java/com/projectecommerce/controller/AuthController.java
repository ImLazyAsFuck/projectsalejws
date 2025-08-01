package com.projectecommerce.controller;

import com.projectecommerce.security.principal.CustomUserDetails;
import com.projectecommerce.model.dto.request.*;
import com.projectecommerce.model.dto.response.*;
import com.projectecommerce.model.entity.User;
import com.projectecommerce.service.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<APIResponse<Void>> register(@ModelAttribute @Valid RegisterDTO dto) {
        authService.register(dto);
        return ResponseEntity.ok(APIResponse.<Void>builder()
                .success(true)
                .message("Đăng ký thành công")
                .timeStamp(LocalDateTime.now())
                .build());
    }

    @PostMapping("/login")
    public ResponseEntity<APIResponse<JWTResponse>> login(@RequestBody @Valid LoginDTO dto) {
        return ResponseEntity.ok(authService.login(dto.getUsername(), dto.getPassword()));
    }

    @PostMapping("/verify")
    public ResponseEntity<APIResponse<Void>> verify(@AuthenticationPrincipal CustomUserDetails userDetails) {
        User user = userDetails.getUser();
        authService.verify(user);
        return ResponseEntity.ok(APIResponse.<Void>builder()
                .success(true)
                .message("Xác thực tài khoản thành công")
                .timeStamp(LocalDateTime.now())
                .build());
    }

    @GetMapping("/profile")
    public ResponseEntity<APIResponse<UserSummaryDTO>> getProfile(@AuthenticationPrincipal CustomUserDetails userDetails) {
        User user = userDetails.getUser();
        UserSummaryDTO dto = authService.getProfile(user);
        return ResponseEntity.ok(APIResponse.<UserSummaryDTO>builder()
                .data(dto)
                .success(true)
                .message("Lấy thông tin người dùng thành công")
                .timeStamp(LocalDateTime.now())
                .build());
    }

    @PutMapping("/profile")
    public ResponseEntity<APIResponse<Void>> updateProfile(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestBody @Valid UpdateProfileDTO dto) {
        User user = userDetails.getUser();
        authService.updateProfile(user, dto);
        return ResponseEntity.ok(APIResponse.<Void>builder()
                .success(true)
                .message("Cập nhật thông tin thành công")
                .timeStamp(LocalDateTime.now())
                .build());
    }

    @PutMapping("/change-password")
    public ResponseEntity<APIResponse<Void>> changePassword(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            @RequestBody @Valid ChangePasswordDTO dto) {
        User user = userDetails.getUser();
        authService.changePassword(user, dto);
        return ResponseEntity.ok(APIResponse.<Void>builder()
                .success(true)
                .message("Đổi mật khẩu thành công")
                .timeStamp(LocalDateTime.now())
                .build());
    }
}
