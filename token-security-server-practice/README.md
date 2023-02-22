# 인증 서버 구현
간단하게 인증서버를 만들어본다.

SpringBoot version : 3.0.2  
java version : 17


## Controller
- /user/add
  - 사용자를 추가한다.
- /user/auth
  - 사용자를 인증하고 OTP가 포함된 SMS를 보낸다.
- /otp/check
  - OTP 값이 인증 서버가 특정 사용자를 위해 이전에 생성한 값인지 확인한다.

구현 확인은 `security-http-request.http` 사용