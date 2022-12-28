# Spring Security In Action java 17로 바꾸기
![](/Users/a000/Desktop/Untitled.png)

## Security 5.4.0 이후 변화 (WebSecurityConfigurerAdapter 안쓰게 되면서)
- [Authorize HttpServletRequests 로 변경](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [Enable Logging for Spring Security](https://www.baeldung.com/spring-security-enable-logging)
- [Spring Security reference category](https://www.baeldung.com/category/spring/spring-security)
- [Spring Security junit5 test reference](https://docs.spring.io/spring-security/reference/servlet/test/method.html)

## Security 필터 설정
- anyRequest().authenticated()
  - 모든 리소스 사용자는 권한(인증)을 완료해야 접근 가능하다.

## AuthenticationProvider
- CustomAuthenticationProvider.class 를 통해 인증을 담당한다는 것을 알 수 있었다.
- 커스텀을 만들고 싶다면  AuthenticationProvider interface 를 구현하면 된다. 

## UserDetails
- **절대 주의! :** JPA 엔티티 클래스와 UserDetails와 하나의 클래스로 만들지 않는다. 하나의클래스는 한개의 책임만 같도록 구성한다. (80p.) 
- User 를 만들려면 UserDetails를 구현하면 된다.    
```java
public class User implements UserDetails {
    //  ...생략
} 
```
- 빌더 클래스로 만들수도 있다.
```java
User.UserBuilder builder1 = User.withUsername("kurt"); // 우선 주어진 사용자 이름으로 사용자 생

UserDetails u1 = builder1
                 .password("12345")
                 .authorities("read", "write")
                 .passwordEncoder(p -> encode(p)) // 함호 인코더는 인코딩을 수행하는 함수 일뿐.
                 .accountExpired(false)
                 .disabled(true)
                 .build();
```

## UserDetailsService
- UserDetailsService.interface 는 한 메서드만 포함한다.
```java
public interface UserDetailsService {

    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
}
```
- 메서드를 호출해 주어진 사용자 이름을 가진 사용자의 정보를 얻는다.
- 물론 반환되는 값은 UserDetails 계약의 구현이다.
- 아키텍처 이미지를 보면 AuthenticationProvider는 인증 논리에서 UserDetailsService를 통해 사용자 세부 정보를 로드한다.
- 추가로 확장을 원할땐 UserDetailsManager interface를 구현하면 된다. 사용자 생성, 변경 삭제와 관련된 동작을 추가할 수 있다.
- 스프링 시큐리티는 UserDetailsManager 계약의 여러 구현을 제공한다. 이러한 구현에는 InMemoryUserDetailsManager, JdbcUserDetailsManager, LdapUserDetailsManager가 있다.
- JdbcUserDetailsManager는 JDBC를 직접 이용하므로 애플리케이션이 다른 프레임워크에 고정되지 않는다는 이점이 있다.(91p. 추후 구현)

## PasswordEncoder
- passwordEncoder interface 는 두개의 추상 메서드와 기본 구현이 있는 메서드 하나를 정의한다.
```java
public interface PasswordEncoder {
    // 문자열을 변환해 반환한다. 즉, 암호의 해시를 제공하거나 암호화를 수행하는 일을 한다.
    String encode(CharSequence rawPassword);

    // 인코딩된 문자열이 원시 암호와 일치하는지 확인
    // 지정된 암호를 인증 프로세스에서 알려진 자격 증명의 집합을 대상으로 비교한다.
    boolean matches(CharSequence rawPassword, String encodedPassword);

    // true를 반환하도록 재정의하면 인코딩된 암호를 보안향상을 위해 다시 인코딩한다.
    default boolean upgradeEncoding(String encodedPassword) {
        return false;
    }
}
```
- 직접 구현해도 되지만 스프링에서 제공된 구현을 선택해도 된다. (각 암호 구현 내용들 : 101p.)
  - NoOpPasswordEncoder : 암호 인코딩 하지 않고 일반 텍스트로 유지 **(실제 시나리오 사용X)** 
  - StandardPasswordEncoder : SHA-256 사용. **(이 구현은 이제 구식이므로 사용X)**
  - Pbkdf2PasswordEncoder : PBKDF2를 사용.
  - BCryptPasswordEncoder : bcrypt 강력 해싱 함수로 인코딩.
  - SCryptPasswordEncoder : scrypt 해싱 함수로 인코딩

## DelegatingPasswordEncoder를 이용한 여러 인코딩 전략
- 운영 단계에서 일반적인 시나리오는 특정 애플리케이션 버전부터 인코딩 알고리즘이 변경된 경우이다.
```java
@Configuration
public class ProjectConfig {
    
    // ...생략
    
    @Bean
    public PasswordEncoder passwordEncoder(){
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
        
        return new DelegatingPasswordEncoder("bcrypt", encoders);
    }
}
```
- 접두사를 기준으로 올바른 PasswordEncoder 구현을 선택한다. 접두사가 없으면 `DelegatingPasswordEncoder`는 기본 인코더를 이용하며 위 코드는 `bcrypt`를 사용했다.
- 암호인코더는 아래 처럼 생겼다. 
```text
{bcrypt}@&2xoni#NnuibA/#dau1$@abic...
```
- 지금까지 설명을 위해 썼지만 PasswordEncoderFactories 클래스에서 정적 메소드를 지원해준다.
```java
PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
```

## KeyGenerator 키 생성기 이용
- 키 생성기는 특별한 종류의 키를 생성하는 객체로서 일반적으로 암호화나 해싱 알고리즘에 필요하다.
-`BytesKeyGenerator` 및 `StringKeyGenerator`는 키 생성기의 두 가지 유형을 나타내는 인터페이스 이며 팩터리 클래스 `KeyGenerators`로 직접 만들 수 있다.
- `StringKeyGenerator` 계약의 정의는 다음과 같다.
```java
public interface StringKeyGenerator {
    // 생성기는 키 값을 나타내는 문자열 하나를 반환하는 메서드
    String generateKey();
}
```
- 다음 코드는 `StringKeyGenerator` 인스턴스를 얻고 솔트 값을 가져오는 방법이다.
```java
// 해당 생성기는 8바이트 키를 생성하고 이를 16진수 문자열로 인코딩하며 메서드는 이러한 작업의 결과를 문자열로 반환한다.
StringKeyGenerator keyGenerator = keyGenerators.string();
String salt = keyGenerator.generateKey();
```
`BytesKeyGenerator` 인터페이스 및 복호화 작업은 추후 추가.(109p.)

##  


