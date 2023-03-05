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



# AuthenticationProvider 의 이해

### 요청하는 엔티티가 인증되지 않는다.

- 애플리케이션이 사용자를 인식하지 못해 권한 부여 프로세스에 위임 하지 않고 요청을 거절한다. 클라이언트에 보통 401 권한 없음을 반환한다.

### 요청하는 엔티티가 인증된다.

- 요청자의 세부 정보가 저장돼 있어 애플리케이션이 이를 권한 부여에 이용할 수 있다. 현재 인증된 요청에 대한 세부 정보는 SecurityContext 인터페이스의 인스턴스에 저장된다.

엔터프라이즈 애플리케이션에는 사용자 이름과 암호 기반의 기본 인증 구현이 적합하지 않을 수 있다. 이게 무슨 뜻이냐 실제로 서비스에선 지문인증, sms 받아서 인증, 애플리케이션에 표시된 코드를 이용해 인증등 다른 방법의 인증들이 존재한다. 어떠한 시나리오가 나오더라도 구현 할 수 있게 해주는것이 프레임워크의 목적이다.

스프링에선 AuthenticationProvider 계약으로 모든 시나리오를 구현할 수 있다. Authetication 인터페이스를 구현하고 AuthenticationProvider 로 맞춤형 인증 논리를 구축한다.

## 맞춤형 인증 만들기

```java
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails u = userDetailsService.loadUserByUsername(username);
        if (passwordEncoder.matches(password, u.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, u.getAuthorities());
        } else {
						// BadCredentialsException은 AuthenticationException을 상속한다.
            throw new BadCredentialsException("Something went wrong!");
        }
    }

    @Override
    public boolean supports(Class<?> authenticationType) {
        return authenticationType.equals(UsernamePasswordAuthenticationToken.class);
    }
}
```

1. AuthenticationProvider 계약을 구현하는 클래스를 선언한다.
2. 새 AuthenticationProvider가 어떤 종류의 Authentication 객체를 지원할지 결정한다.
  1. 정의하는 AuthenticationProvider 가 지원하는 인증 유형을 나타내도록 supports 메서드를 재정의 한다.
  2. authentication 메서드를 재정의해 인증 논리를 구현한다.
3. 새 AuthenticationProvider 구현의 인스턴스를 스프링 시큐리티에 등록한다.

만들었으니 구성 클래스에 AuthenticationProvider 를 등록해주기만 하면 된다.

- [스프링 레퍼런스](https://www.baeldung.com/spring-security-authentication-provider)

# SecurityContext
AuthenticationManager는 인증 프로세스를 성공적으로 완료한 후 요청이 유지되는 동안 Authentication 인스턴스를 저장한다.
Authentication 객체를 저장하는 인스턴스를 보안 컨텍스트라 부른다.

## SecurityContext interface

```java
public interface SecurityContext extends Serializable {

		Authentication getAuthentication();
		void setAuthentication(Authentication authentication);
}
```

위 계약 정의를 보면 SecurityContext의 주 책임은 Authentication 객체를 저장하는 것이다.
그렇다면 SecurityContext 자체는 어떻게 관리될까?

스프링 시큐리티는 관리자 역할을 하는 객체로 SecurityContext를 관리하는 세 가지 전략을 제공한다.
이 객체를 SecurityContextHolder 라 부른다.

- **MODE_THREADLOCAL**
  - 각 스레드가 보안 컨텍스트에 각자의 세부 정보를 저장할 수 있게 해준다. 요청당 스레드 방식의 웹 애플리케이션에서는 각 요청이 개별 스레드를 가지므로 이는 일반적인 접근법이다.
- **MODE_INHERITABLETHREADLOCAL**
  - MODE_THREADLOCAL 과 비슷하지만 비동기 메서드의 경우 보안 컨텍스트를 다음 스레드로 복사하도록 스프링 시큐리티에 지시한다. 이 방식으로 @Async 메서드를 실행하는 새 스레드가 보안 컨텍스트를 상속하게 할 수 있다.

    이 방식은 자체적으로 쓰레드를 만들게 되면 적용되지 않는다. 그 이유는 프레임워크가 코드에서 생성한 쓰레드에 대해 모르기 때문이다 → DelegatingSecurityContextRunnable로 보안 컨텍스트 전달 (책 131p. 참고)

- **MODE_GLOBAL**
  - 애플리케이션의 모든 스레드가 같은 보안 컨텍스트 인스턴스를 보게 한다.


# AuthenticationEntryPoint
인증이 실패했을 때의 응답을 맞춤 구성 하려면 `AuthenticationEntryPoint`를 구현하면 된다.

`AuthenticationEntryPoint` 의 commence() 메서드는 `httpServletRequest` , `httpServletResponse`, 인증 실패를 일으킨 `AuthenticationException` 을 받는다.

이 인터페이스는 스프링 시큐리티 아키텍처에서 `ExceptionTranslationManager` 라는 구성 요소에서 직접 사용되며, 그 구성 요소는 필터 체인에서 투척된 모든 AccessDeniedException, AuthenticationException 을 처리한다.

## AuthenticationEntryPoint 구현

```java
public class CustomEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException {
        httpServletResponse.addHeader("message", "너는 에러를 낸것이야");
        httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value());
    }
}
```

구현을 했으니 HTTP Basic 인증을 위해 등록을 한다.

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic(c -> {
            c.realmName("OTHER");
            c.authenticationEntryPoint(new CustomEntryPoint());
        });
        http.authorizeRequests().anyRequest().authenticated();
    }
}
```

자바 17의 경우 WebSecurityConfigurerAdapter이 @Deprecated 되었기 때문에 `filterChain` 에 넣어주면 된다.

## java 17 (Spring Security 5.7.0 이후) 적용
```java
@Configuration
public class WebAuthorizationConfig {

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().authenticated())
                .httpBasic();

        http.httpBasic(c->
              c.realmName("aaa")
	            c.authenticationEntryPoint(new CustomEntryPoint());
        );

        return http.build();
    }

}

```
## 인증방식을 양식 기반 로그인으로 변경하고 싶으면..?

httpBasic() 대신 formLogin() 메서드를 출력한다.

```java
@Configuration
public class WebAuthorizationConfig {

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
                        .anyRequest().authenticated())
                .httpBasic();

        http.formLogin();
        http.authorizeRequests().anyRequest().authenticated();
	
        );

        return http.build();
    }

}
```
로그인에 성공 했을 때의 논리를 맞춤 구성 하고 싶다면 .defaultSuccessUrl 를 사용하면 된다.

```java
@Configuration
public class WebAuthorizationConfig {

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.formLogin().defaultSuccessUrl("/home", true);
        http.authorizeRequests().anyRequest().authenticated();
	
        );

        return http.build();
    }

}
```

더 세부적인 맞춤 구성이 필요하다면 **AuthenticationSuccessHandler 및 AuthenticationFailureHandler** 객체를 이용할 수 있다.

## AuthenticationSuccessHandler 구현

```java
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException {
        var authorities = authentication.getAuthorities();

        var auth = authorities.stream()
                    .filter(a -> a.getAuthority().equals("read"))
                    .findFirst();

        if (auth.isPresent()) { // read 권한이 있으면 /home 으로 리다이렉션
            httpServletResponse.sendRedirect("/home");
        } else {
            httpServletResponse.sendRedirect("/error");
        }
    }
}
```

## **AuthenticationFailureHandler 구현**

```java
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e)  {
        httpServletResponse.setHeader("failed", LocalDateTime.now().toString());
    }
}
```

핸들러를 만들어 줬으니 구성 클래스에 핸들러 객체를 등록해준다.

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    private CustomAuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
            .successHandler(authenticationSuccessHandler)
            .failureHandler(authenticationFailureHandler)
        .and()
            .httpBasic();

        http.authorizeRequests()
                .anyRequest().authenticated();
    }
}
```

# 사용자 권한을 기준으로 모든 엔드포인트에 접근 제한

hasAuthority() - 애플리케이션이 제한을 구성하는 하나의 권한만 매개변수로 받는다. 해당 권한이 있는 사용자만 엔드포인트를 호출할 수 있다.

hasAnyAuthority() - 애플리케이션이 제한을 구성하는 권한을 하나 이상 받을 수 있다. 개인적으로 이 메서드를 주어진 권한중 하나만 해당하면 이라고 외웠다.

access() - SpEl 을 기반으로 권한 부여 규칙을 정한다. 권장방식은 아니니 이런 방법이 있다고 알아두자.

## access() 사용 예제

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

				// 사용자에게 읽기 권한이 있어야 하지만 삭제 권한은 없어야 함을 알림
        String expression = "hasAuthority('read') and !hasAuthority('delete')";
        http.authorizeRequests()
                .anyRequest().access(expression);
    }
```

# 사용자 역할을 기준으로 모든 엔드포인트에 대한 접근을 제한

hasRole() - 애플리케이션이 요청을 승인할 하나의 역할 이름을 매개변수로 받는다.

hasAnyRole() - 애플리케이션이 요청을 승인할 여러 역할 이름을 매개변수로 받는다.

access() - SpEl 을 기반으로 권한 부여 규칙을 정한다.

authorities() 를 사용하면 앞에 “ROLE_ “ 접두사를 포함해야 하지만 roles() 메서드를 사용하면 접두사를 포함하지 않아도 된다. 이유는 구현체를 보면 알 수 있다.

- User.class 메서드 구현 보기

    ```java
    public UserBuilder roles(String... roles) {
                List<GrantedAuthority> authorities = new ArrayList(roles.length);
                String[] var3 = roles;
                int var4 = roles.length;
    
                for(int var5 = 0; var5 < var4; ++var5) {
                    String role = var3[var5];
                    Assert.isTrue(!role.startsWith("ROLE_"), () -> {
                        return role + " cannot start with ROLE_ (it is automatically added)";
                    });
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                }
    
                return this.authorities((Collection)authorities);
            }
    
    public UserBuilder authorities(GrantedAuthority... authorities) {
                return this.authorities((Collection)Arrays.asList(authorities));
            }
    
    public UserBuilder authorities(Collection<? extends GrantedAuthority> authorities) {
                this.authorities = new ArrayList(authorities);
                return this;
            }
    ```


# roles() 메서드 사용

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();

        var user1 = User.withUsername("john")
                        .password("12345")
                        .roles("ADMIN")
                        .build();

        var user2 = User.withUsername("jane")
                        .password("12345")
                        .roles("MANAGER")
                        .build();

        manager.createUser(user1);
        manager.createUser(user2);

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

        http.authorizeRequests().anyRequest().hasRole("ADMIN");
    }
}
```

# authorities() 사용

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();

        var user1 = User.withUsername("john")
                        .password("12345")
                        .authorities("ROLE_ADMIN")
                        .build();

        var user2 = User.withUsername("jane")
                        .password("12345")
                        .authorities("ROLE_MANAGER")
                        .build();

        manager.createUser(user1);
        manager.createUser(user2);

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

        http.authorizeRequests().anyRequest().hasRole("ADMIN");
    }
}
```

# access() 는 언제 활용할까???

지금까지 권한 부여, 역할 부여만 알아봤지만 이벤트 로그인등 특수한 상황에 활용이 가능하다.

예로 정오 이후에만 엔드포인트 접근을 활용할 수 있다.

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();

        var user1 = User.withUsername("john")
                .password("12345")
                .authorities("read")
                .build();

        var user2 = User.withUsername("jane")
                .password("12345")
                .authorities("read", "write", "delete")
                .build();

        manager.createUser(user1);
        manager.createUser(user2);

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

        http.authorizeRequests()
                .anyRequest().access("T(java.time.LocalTime).now().isAfter(T(java.time.LocalTime).of(12, 0))");
    }
}
```

# 모든 엔드포인트에 대한 접근 제한

- denyAll() - 모든 요청 엑세스를 허용
- permitAll() - 모든 요청 엑세스를 거부
- authenticated() - 인증된 사용자만 요청 엑세스 허용

## 모든 엔드포인트 접근은 언제 사용할까???

다음에 생각하기 편하게 미리 상황을 생각해 적어봄.

1. 경로 변수로 이메일을 받는다고 했을때 com 요청이면 허용 net이면 허용하지 않음.
2. 게이트웨이를 사용해 서버를 구성했을때 특정 마이크로 서비스에 해당하는 것만 허용하고 나머진 denyAll() 처리한다.


# 시큐리티 권한 부여 : 제한 적용
운영 단계 애플리케이션에선 모든 요청이 동일한 규칙을 적용하는 경우는 많지 않고, 일부 엔드포인트는 특정 사용자만 호출할 수 있고 나머지 엔드포인트는 모든 사용자가 호출할 수 있는 경우가 많다.

- MVC 선택기 - 경로에 MVC 식을 이용해 엔드포인트를 선택한다.
- 앤트 선택기 - 경로에 앤트 식을 이용해 엔드포인트를 선택한다.
- 정규식 선택기 - 경로에 정규식(regex)을 이용해 엔드포인트를 선택한다.

# MVC 선택기

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();

        var user1 = User.withUsername("john")
                .password("12345")
                .roles("ADMIN")
                .build();

        var user2 = User.withUsername("jane")
                .password("12345")
                .roles("MANAGER")
                .build();

        manager.createUser(user1);
        manager.createUser(user2);

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

        http.authorizeRequests()
                .mvcMatchers("/hello").hasRole("ADMIN")
                .mvcMatchers("/ciao").hasRole("MANAGER")
                .anyRequest().permitAll();
                //.anyRequest().denyAll();
                //.anyRequest().authenticated();
    }

		//첫번째 시나리오
		@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

        http.authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/a")
								.authenticated() // HTTP GET 방식으로 /a 경로를 요청하면 앱이 사용자를 인증해야한다.
                .mvcMatchers(HttpMethod.POST, "/a")
								.permitAll() // HTTP POST 방식 /a 경로 요청은 모두 허용
                .anyRequest().denyAll(); // 나머지 요청 모두 거부

        http.csrf().disable();
    }

		//두번째 시나리오
		@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

        http.authorizeRequests()
                .mvcMatchers( "/a/b/**").authenticated() // /a/b 붙은 모든 경로 인증필요.
                .anyRequest().permitAll();

        http.csrf().disable();
    }

		// 세번째 시나리오
		@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();

        http.authorizeRequests()
                .mvcMatchers( "/product/{code:^[0-9]*$}").permitAll() // 길이상관없이 숫자를 포함하는 문자열
                .anyRequest().denyAll();
    }
}
```

# 앤트 선택기 208p.

최대한 MVC 선택기를 이용하는것이 좋다. MVC 선택기를 이용하면 스프링의 경로 및 작업 매핑과 관련한 몇 가지 위험을 예방할 수 있다. 그 이유는 권한 부여 규칙을 위해 경로를 해석하는 방법과 스프링이 경로를 엔드포인트에 매핑하기 위해 해석하는 방법이 같기 때문이다. 반면 앤트 선택기를 이용하려면 권한 부여 규칙을 적용할 모든 경로에 확실하게 적용되게 식을 작성해야 한다.

### 앤트 선택기는 확실하게 적용되게 식을 작성해라????

간단하면서도 보안의 관점에서 상당한 영향을 미치는 사례로 스프링은 동일한 작업에 대한 모든 경로에(`/hello`) 대해 경로 뒤에 다른 /를 추가해도 해석할 수 있다. 이 경우 `/hello` 와 `/hello/` 는 같은 메서드를 호출한다.  MVC 선택기로  `/hello`  경로에 대한 보안을 구성하면 `/hello/` 경로도 자동으로 같은 규칙으로 보호ㅛ6된다. 앤트는 그렇지 않다. 이를 모르면 의도치 않게 경로를 보호되지 않는 상태로 방치할 수 있다.

# 정규식 선택기 213p.

MVC 선택기와 앤트 선택기로 구현할 수 없는 복잡한 선택기 구현이 필요하면 사용한다.

# 권한 필터 수행 순서
엔드포인트를 모두 접근할 수 있게 설계했다면 인증을 위한 사용자 이름과 암호를 제공하지 않아도 호출할 수 있고, 이 경우는 시큐리티는 인증을 수행하지 않는다. 하지만 굳이 사용자 이름과 암호를 제공했다면 스프링 시큐리티는 인증 프로세스에서 이를 확인하며, 확인되지 않으면(로그인 실패) 인증이 실패한다 (401)

사용자 확인이 되었지만 권한에서 문제가 생길경우 403에러를 발생한다. 이렇듯 어떠한 문제가 생겼을때 기대하는 에러코드가 정해져 있기에 커스텀해 사용할땐 이런 부분도 신경써야 한다.

즉. 시큐리티는 권한 필터보다 인증 필터를 먼저 실행한다.
![시큐리티 필터 순서](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/740b2a16-0951-4143-b936-e9669b968d6f/Untitled.png)

시큐리티 필터 순서

# 체인에서 기존 필터 뒤,앞 필터 추가

필터 체인에서 기존 필터 뒤,앞에 맞춤형 필터를 추가하는 과정은 기존 필터 다음에 원하는 논리를 실행할때 사용한다.

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
				
        // 필터 체인에서 BasicAuthenticationFilter 앞에 RequestValidationFilter 를 추가한다.
        http.addFilterBefore(
                new RequestValidationFilter(),
                BasicAuthenticationFilter.class)
                // BasicAuthenticationFilter 뒤에 AuthenticationLoggingFilter 를 추가한다.
            .addFilterAfter(
                new AuthenticationLoggingFilter(),
                BasicAuthenticationFilter.class)
            .authorizeRequests()
                .anyRequest()
                    .permitAll();
    }
}
```

위 코드를 실행한다고 가정해보면 `RequestValidationFilter` 가 먼저 실행되고 요청이 정상적이라면  `BasicAuthenticationFilter` 가 실행된다. `BasicAuthenticationFilter` 가 끝나면 `AuthenticationLoggingFilter` 가 실행되기에 로그가 남겨진다.

# 주의!!!

**addFilterAt - 지정된 필터의 순서에 커스텀 필터 추가**

기존 필터의 위치에 다른 필터를 적용하면 필터가 대체된다고 생각할 수 있지만 그렇지 않다. 같은 위치에 여러 필터를 추가하면 필터가 실행되는 순서가 보장되지 않는다. 순서가 정해져 있는것이 이치에 맞다. 순서를 알아야 논리를 이해하고 유지 관리하기 쉽다.

# CORS
기본적으로 브라우저는 사이트가 로드된 도메인 이외의 도메인에 대한 요청을 허용하지 않는다.
애플리케이션이 두 개의 서로 다른 도메인 간에 호출하는 것은 모두 금지된다. 그러나 그러한 호출이 필요할 때가 있다. 이때 CORS를 이용하면 애플리케이션이 요청을 허용할 도메인, 그리고 공유할 수 있는 세부 정보를 지정할 수 있다. CORS 메커니즘은 HTTP 헤더를 기반으로 작동하며 가장 중요한 헤더는 다음과 같다!!

- **Access-Control-Allow-Origin**
  - 도메인의 리소스에 접근할 수 있는 외부 도메인(원본)을 지정한다.
- **Access_Control-Allow-Methods**
  - 다른 도메인에 대해 접근을 허용하지만 특정 HTTP 방식만 허용하고 싶을 때 일부 HTTP 방식을 지정할 수 있다. 예를 들어 [example.com](http://example.com)이 일부 엔드포인트를 호출할 수 있게 하면서 HTTP GET만 허용할 수 있다.
- **Access-Control-Allow-Headers**
  - 특정 요청에 이용할 수 있는 헤더에 제한을 추가한다.


## 애플리케이션에서 CORS를 구성하지 않고 교차 출처를 호출하면 어떤 일이 생길까???

애플리케이션은 요청을 응답받을 때 여기에 서버가 수락하는 출처가 나열된 Access-Control-Allow-Origin 헤더가 있다고 예상한다. 스프링 시큐리티의 기본 동작과 같이 이 헤더가 없으면 브라우저는 응답을 수락하지 않는다.

# 1. `@CorssOrigin` 어노테이션으로 CORS 정책 적용

`@CorssOrigin` 어노테이션으로 다른 도메인에서의 요청을 허용하도록 CORS를 구성하는 방법이 있다. 엔드포인트 정의하는 메서드 바로 위에 배치하고 허용된 출처와 메서드를 이용해 구성할 수 있다.

```java
@PostMapping("/test")
    @ResponseBody
    @CrossOrigin("http://localhost:8080") // 어노테이션으로 CORS 정책 적용
    public String test() {
        logger.info("Test method called");
        return "HELLO";
    }
```

- 장점 : 엔드포인트가 정의되는 위치에서 직접 규칙을 지정하면 규칙이 투명해진다.
- 단점 : 코드가 장황해지고 많은 코드를 반복해야 할 수 있다. 또한 새로 구현하는 엔드포인트에 어노테이션 추가를 잊어버릴 수도 있다.

CORS 구성을 한곳에서 정의해야 한다면 해당 어노테이션을 이용하자!

# 2. `CorsConfigurer` 로 CORS 적용

```java
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

				// cors()를 호출해 CORS 구성을 정의한다. 여기에 허용되는 출처와 메서드를 설정하는 CorsConfiguration 객체를 생성한다.
        http.cors(c -> {
            CorsConfigurationSource source = request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("*"));
                config.setAllowedMethods(List.of("*"));
                return config;
            };
            c.configurationSource(source);
        });

        http.csrf().disable();

        http.authorizeRequests()
                .anyRequest().permitAll();
    }
}
```

`cors()` 는 `Customizer<CorsConfigurer>` 객체를 매개 변수로 받는다.
이 객체를 위해 HTTP 요청의 `CorsConfiguration` 을 반환하는 `CorsConfigurationSource`를 설정했다.

`CorsConfigurationSource`은 허용되는 출처, 메서드, 헤더를 지정하는 객체다. 이 방식을 이용하려면 최소한 허용할 출처와 메서드를 지정해야 하며 출처만 지정하면 애플리케이션이 요청을 허용하지 않는다.

람다로 구현했지만 실제 애플리케이션을 작성할땐 클래스 분리를 꼭 하자!!!!
