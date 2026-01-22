# `msstore_cdn`

A simple util that forces Microsoft Store to use the best CDN possible.

## CDN Sources

```rust
const DNS_SOURCES: &[DnsSource] = &[
    DnsSource {
        name: "China Telecom (CTCDN)",
        domain: "httpdns.ctdns.cn",
    },
    DnsSource {
        name: "Baidu Cloud (BDYDNS)",
        domain: "tlu.dl.delivery.mp.microsoft.com.a.bdydns.com",
    },
    DnsSource {
        name: "DNSE8 / Tencent Cloud",
        domain: "tlu.dl.delivery.mp.microsoft.com.cdn.dnse8.com",
    },
    DnsSource {
        name: "Kingsoft Cloud",
        domain: "tlu.dl.delivery.mp.microsoft.com.download.ks-cdn.com",
    },
    DnsSource {
        name: "XinLiu Cloud (CNGSLB)",
        domain: "wsdt-xlc.tlu.dl.delivery.mp.microsoft.com.z.cngslb.com",
    },
    DnsSource {
        name: "Fastly (International)",
        domain: "fg.microsoft.map.fastly.net",
    },
    DnsSource {
        name: "Akamai (International)",
        domain: "tlu.dl.delivery.mp.microsoft.com-c.edgesuite.net",
    },
    DnsSource {
        name: "GlobalCDN",
        domain: "cl-glcb907925.globalcdn.co",
    },
];
```

## License

GPL 3.0 or later. See [LICENSE](./LICENSE) for details.
