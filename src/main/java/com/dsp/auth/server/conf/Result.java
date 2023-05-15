package com.dsp.auth.server.conf;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Data
public class Result<T> implements Serializable {

    // http状态码
    private int status;

    // 自定义响应编码
    private int code = 0;

    // 响应返回信息
    private String message;

    // 请求路径
    private String path;

    // 响应返回数据
    private T data;

    // 响应时间戳
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date timestamp = new Date();

    // 链路信息
    private String traceId;

    public Map<String, Object> toModel() {
        Map<String, Object> result = new HashMap<>(16);
        result.put("code", this.code);
        result.put("message", this.message);
        result.put("path", this.path);
        result.put("data", this.data);
        result.put("status", this.status);
        result.put("timestamp", this.timestamp);
        result.put("traceId", this.traceId);
        return result;
    }

}
