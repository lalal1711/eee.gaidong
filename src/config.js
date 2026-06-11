// ============================================================
// src/config.js - Configuration and global variables
// ============================================================

export const VERSION = '2026-06-09 13:29:03';

// Mutable configuration object (properties can be mutated by importing module)
export const Config = {
	反代IP: '',
	启用SOCKS5反代: null,
	启用SOCKS5全局反代: false,
	我的SOCKS5账号: '',
	parsedSocks5Address: {},
	缓存SOCKS5白名单: null,
	缓存反代IP: undefined,
	缓存反代解析数组: undefined,
	缓存反代数组索引: 0,
	启用反代兜底: true,
	调试日志打印: false,
	SOCKS5白名单: ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'],
	TCP并发拨号数: 2,
	预加载竞速拨号: false,
};

// Security: Login brute-force protection
export const 登录频率限制Map = new Map();
export const 登录频率限制窗口 = 10 * 60 * 1000;
export const 登录频率限制最大尝试 = 8;
export const 登录频率限制封禁时间 = 30 * 60 * 1000;

// WS / streaming constants
export const WS早期数据最大字节 = 8 * 1024;
export const WS早期数据最大头长度 = Math.ceil(WS早期数据最大字节 * 4 / 3) + 4;
export const 上行合包目标字节 = 16 * 1024;
export const 上行队列最大字节 = 16 * 1024 * 1024;
export const 上行队列最大条目 = 4096;
export const 下行Grain包字节 = 32 * 1024;
export const 下行Grain尾部阈值 = 512;
export const 下行Grain静默毫秒 = 0;

// Proxy signature
export const 查杀特征码 = (Proxy.name + "IP").toUpperCase();

// Pages static page URL
export const Pages静态页面 = 'https://edt-pages.github.io';
