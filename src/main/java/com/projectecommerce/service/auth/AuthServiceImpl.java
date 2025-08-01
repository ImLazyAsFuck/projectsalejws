package com.projectecommerce.service.auth;

import com.projectecommerce.security.jwt.JWTProvider;
import com.projectecommerce.mapper.UserMapper;
import com.projectecommerce.model.dto.request.*;
import com.projectecommerce.model.dto.response.*;
import com.projectecommerce.model.entity.Role;
import com.projectecommerce.model.entity.User;
import com.projectecommerce.model.enums.ERole;
import com.projectecommerce.repository.RoleRepository;
import com.projectecommerce.repository.UserRepository;
import com.projectecommerce.service.cloudinary.CloudinaryService;
import com.projectecommerce.utils.exception.ConflictException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.LocalDate;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final CloudinaryService cloudinaryService;

    @Override
    @Transactional
    public void register(RegisterDTO dto) {
        if (userRepository.existsByUsername(dto.getUsername()))
            throw new IllegalArgumentException("Username đã tồn tại");

        if (userRepository.existsByEmail(dto.getEmail()))
            throw new IllegalArgumentException("Email đã tồn tại");

        if (userRepository.existsByPhone(dto.getPhone()))
            throw new IllegalArgumentException("Số điện thoại đã tồn tại");

        Role role = roleRepository.findByName(ERole.CUSTOMER)
                .orElseThrow(() -> new IllegalCallerException("Vai trò không hợp lệ"));

        User user = User.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .email(dto.getEmail())
                .fullName(dto.getFullName())
                .address(dto.getAddress())
                .phone(dto.getPhone())
                .roles(Set.of(role))
                .avatar(null)
                .status(true)
                .isVerify(false)
                .isLogin(false)
                .isDeleted(false)
                .createAt(LocalDate.now())
                .updateAt(LocalDate.now())
                .deletedAt(null)
                .build();

        userRepository.save(user);
    }

    @Override
    public APIResponse<JWTResponse> login(LoginDTO dto) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword()));

        User user = userRepository.findByUsername(dto.getUsername())
                .orElseThrow(() -> new ConflictException("Không tìm thấy người dùng"));

        String token = jwtTokenProvider.generateToken(dto.getUsername());
        String refreshToken = jwtTokenProvider.generateRefreshToken(dto.getUsername());
        ERole role = user.getRoles().iterator().next().getName();

        return APIResponse.<JWTResponse>builder()
                .data(new JWTResponse(
                        token, refreshToken, user.getId(), user.getUsername(), user.getFullName(),
                        user.getEmail(), user.getAvatar(), user.getAddress(), user.getPhone(), role))
                .success(true)
                .message("Đăng nhập thành công")
                .timeStamp(LocalDateTime.now())
                .build();
    }

    @Override
    public void changePassword(User user, ChangePasswordDTO dto) {
        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword())) {
            throw new ConflictException("Mật khẩu cũ không đúng");
        }
        if(!dto.getOldPassword().equals(dto.getNewPassword())){
            throw new ConflictException("Xác nhận mật khẩu không giống với mật khẩu");
        }

        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        user.setUpdateAt(LocalDate.now());
        userRepository.save(user);
    }

    @Override
    public void verify(User user) {
        if (user.isVerify()) throw new ConflictException("Tài khoản đã xác thực rồi");

        user.setVerify(true);
        userRepository.save(user);
    }

    @Override
    public UserSummaryDTO getProfile(User user) {
        return UserMapper.toUserSummaryDTO(user);
    }

    @Override
    public void updateProfile(User user, UpdateProfileDTO dto) {
        if (userRepository.existsByEmailAndIdNot(dto.getEmail(), user.getId()))
            throw new ConflictException("Email đã được sử dụng");

        if (userRepository.existsByPhoneAndIdNot(dto.getPhone(), user.getId()))
            throw new ConflictException("SĐT đã được sử dụng");

        if (dto.getAvatar() != null && !dto.getAvatar().isEmpty()) {
            try {
                String imageUrl = cloudinaryService.uploadFile(dto.getAvatar());
                user.setAvatar(imageUrl);
            } catch (IOException e) {
                throw new RuntimeException("Tải ảnh lên thất bại", e);
            }
        }

        user.setFullName(dto.getFullName());
        user.setEmail(dto.getEmail());
        user.setAddress(dto.getAddress());
        user.setPhone(dto.getPhone());
        user.setUpdateAt(LocalDate.now());
        userRepository.save(user);
    }
}
