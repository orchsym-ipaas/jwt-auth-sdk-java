package com.jwtauth.common.util;

import java.security.NoSuchAlgorithmException;

/**
 * RSA密钥生成器调用示例
 */
public class RSAGeneratorExample {
    
    public static void main(String[] args) {
        try {
            // 创建RSA密钥对生成器实例（推荐使用2048位或4096位）
            OrchsymRSA256KeyGenerator keyGenerator = new OrchsymRSA256KeyGenerator(2048);
            
            // 方式1：直接使用toString()方法获取格式化的密钥对
            System.out.println("=== RSA 密钥对（格式化输出）===");
            System.out.println(keyGenerator.toString());
            
            // // 方式2：分别获取公钥和私钥对象
            // System.out.println("\n=== 分别获取密钥对象 ===");
            // System.out.println("公钥算法: " + keyGenerator.getPublicKey().getAlgorithm());
            // System.out.println("公钥格式: " + keyGenerator.getPublicKey().getFormat());
            // System.out.println("私钥算法: " + keyGenerator.getPrivateKey().getAlgorithm());
            // System.out.println("私钥格式: " + keyGenerator.getPrivateKey().getFormat());
            
            // 方式3：获取Base64编码的密钥字符串（用于配置文件等）
            // System.out.println("\n=== Base64编码的密钥字符串 ===");
            // String publicKeyBase64 = java.util.Base64.getEncoder().encodeToString(
            //     keyGenerator.getPublicKey().getEncoded());
            // String privateKeyBase64 = java.util.Base64.getEncoder().encodeToString(
            //     keyGenerator.getPrivateKey().getEncoded());
            
            // System.out.println("公钥Base64:");
            // System.out.println(publicKeyBase64);
            // System.out.println("\n私钥Base64:");
            // System.out.println(privateKeyBase64);
            
            // // 方式4：生成不同长度的密钥
            // System.out.println("\n=== 生成4096位密钥 ===");
            // OrchsymRSA256KeyGenerator strongKeyGenerator = new OrchsymRSA256KeyGenerator(4096);
            // System.out.println("4096位公钥:");
            // System.out.println(java.util.Base64.getEncoder().encodeToString(
            //     strongKeyGenerator.getPublicKey().getEncoded()));
            
        } catch (NoSuchAlgorithmException e) {
            System.err.println("生成RSA密钥对时发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}