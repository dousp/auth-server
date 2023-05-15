package com.dsp.auth.server.conf;

public enum ResultCodes {

    /**
     * 401.** 未经授权 Unauthorized 请求要求用户的身份认证
     */
    ACCESS_DENIED(40101, "您没有权限，拒绝访问"), ACCOUNT_DISABLED(40102, "该账户已经被禁用"),
    ACCOUNT_ENDPOINT_LIMITED(40103, "您已经使用其它终端登录,请先退出其它终端"), ACCOUNT_EXPIRED(40104, "该账户已经过期"),
    ACCOUNT_LOCKED(40105, "该账户已经被锁定"), BAD_CREDENTIALS(40106, "用户名或密码错误"), CREDENTIALS_EXPIRED(40107, "该账户密码凭证已过期"),
    INVALID_CLIENT(40108, "客户端身份验证失败"), INVALID_TOKEN(40109, "提供的访问令牌已过期、吊销、格式错误或无效"),
    INVALID_GRANT(40110, "提供的授权授予或刷新令牌无效、已过期或已撤销"), UNAUTHORIZED_CLIENT(40111, "客户端无权使用此方法请求授权码或访问令牌"),
    USERNAME_NOT_FOUND(40112, "用户名或密码错误"), SESSION_EXPIRED(40113, "Session 已过期，请刷新页面后再使用"),

    /**
     * 403.** 禁止的请求，与403对应
     */
    INSUFFICIENT_SCOPE(40301, "TOKEN权限不足，您需要更高级别的权限"), SQL_INJECTION_REQUEST(40302, "疑似SQL注入请求"),

    /**
     * 405.** 方法不允许 与405对应
     */
    HTTP_REQUEST_METHOD_NOT_SUPPORTED(40501, "请求使用的方法类型不支持"),

    /**
     * 406.** 不接受的请求，与406对应
     */
    UNSUPPORTED_GRANT_TYPE(40601, "授权服务器不支持授权授予类型"), UNSUPPORTED_RESPONSE_TYPE(40602, "授权服务器不支持使用此方法获取授权代码或访问令牌"),
    UNSUPPORTED_TOKEN_TYPE(40603, "授权服务器不支持撤销提供的令牌类型"),

    /**
     * 412.* 未经授权 Precondition Failed 客户端请求信息的先决条件错误
     */
    INVALID_REDIRECT_URI(41201, "OAuth2 URI 重定向的值无效"), INVALID_REQUEST(41202, "无效的请求，参数使用错误或无效."),
    INVALID_SCOPE(41203, "授权范围错误"),

    /**
     * 415.* Unsupported Media Type 服务器无法处理请求附带的媒体格式
     */
    HTTP_MEDIA_TYPE_NOT_ACCEPTABLE(41501, "不支持的 Media Type"),

    /**
     * 500.* Internal Server Error 服务器内部错误，无法完成请求
     */
    SERVER_ERROR(50001, "授权服务器遇到意外情况，无法满足请求"),

    /**
     * 503.* Service Unavailable 由于超载或系统维护，服务器暂时的无法处理客户端的请求。延时的长度可包含在服务器的Retry-After头信息中
     */
    SERVICE_UNAVAILABLE(50301, "服务不可用"),

    NO(99999, "nothing");

    // @Schema(title = "结果代码")
    private final int code;

    // @Schema(title = "结果信息")
    private final String message;

    ResultCodes(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

}
