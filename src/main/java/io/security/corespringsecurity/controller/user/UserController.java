package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.service.AccountDetails;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
@Slf4j
public class UserController {

	private final UserService userService;
	private final PasswordEncoder passwordEncoder;
	
	@GetMapping(value="/mypage")
	public String myPage() {
		return "user/mypage";
	}

	@GetMapping(value = "/users")
	public String createUser(Model model) {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(@ModelAttribute AccountDto accountDto) {

		Account account = accountDto.toEntity();

		account.encodePassword(passwordEncoder.encode(account.getPassword()));
		userService.createUser(account);

		return "redirect:/";
	}
}
