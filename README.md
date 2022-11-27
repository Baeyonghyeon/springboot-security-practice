# Spring Security In Action java 17로 바꾸기
![](/Users/a000/Desktop/Untitled.png)

## Security 5.4.0 이후 변화 (WebSecurityConfigurerAdapter 안쓰게 되면서)
- [Authorize HttpServletRequests 로 변경](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [Enable Logging for Spring Security](https://www.baeldung.com/spring-security-enable-logging)
- [참고 래퍼런스](https://www.baeldung.com/category/spring/spring-security)
- 

## Security 필터 설정
- anyRequest().authenticated()
  - 모든 리소스 사용자는 권한(인증)을 완료해야 접근 가능하다.

## AuthenticationProvider
- CustomAuthenticationProvider.class 를 통해 인증을 담당한다는 것을 알 수 있었다.
- 커스텀을 만들고 싶다면  AuthenticationProvider interface 를 구현하면 된다. 

## UserDetails
- **절대 주의! :** JPA 엔티티 클래스와 UserDetails와 하나의 클래스로 만들지 않는다. 하나의클래스는 한개의 책임만 같도록 구성한다. (80p.) 
- User 를 만들려면 UserDetails를 구현하면 된다.    
```
public class User implements UserDetails {
  ...생략
}
```
- 빌더 클래스로 만들수도 있다.
```
User.UserBuilder builder1 = User.withUsername("kurt"); // 우선 주어진 사용자 이름으로 사용자 생

UserDetails u1 = builder1
                 .password("12345")
                 .authorities("read", "write")
                 .passwordEncoder(p -> encode(p)) // 함호 인코더는 인코딩을 수행하는 함수 일뿐.
                 .accountExpired(false)
                 .disabled(true)
                 .build()
```

## UserDetailsService
- UserDetailsService.interface 는 한 메서드만 포함한다.
```
public interface UserDetailsService {

  UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
}
```
- 메서드를 호출해 주어진 사용자 이름을 가진 사용자의 정보를 얻는다.
- 물론 반환되는 값은 UserDetails 계약의 구현이다.
- 아키텍처 이미지를 보면 AuthenticationProvider는 인증 논리에서 UserDetailsService를 통해 사용자 세부 정보를 로드한다.

