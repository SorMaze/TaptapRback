# 镜像只承载已经编译好的静态二进制，不在容器里做 cargo build。
#
# 二进制在本机用 cargo-zigbuild 交叉编译产出：
#   cargo zigbuild --release --target x86_64-unknown-linux-musl
# 产物是完全静态链接的（musl + ring 的 C/汇编由 zig cc 提供），
# 因此基础镜像用 scratch 就够，不需要 libc、不需要任何运行时。
#
# 之所以能用 scratch：reqwest 走的是 rustls + webpki-roots，
# 根证书编译进二进制，不读系统 CA 库；也不需要时区与 shell。
#
# 构建前把二进制放到本文件同级目录（构建上下文）：
#   cp target/x86_64-unknown-linux-musl/release/taptap-rback deploy/taptap-rback
#   docker build -t taptap-rback:0.1.0 deploy/
FROM scratch

# 构建上下文是从 Windows 拷过来的，文件没有 Unix 可执行位（会带成 0644，
# 容器起不来并报 `exec: "/taptap-rback": permission denied`），这里显式给上。
COPY --chmod=0755 taptap-rback /taptap-rback

# scratch 里没有 /etc/passwd，只能用数字 UID 声明非 root 运行。
USER 10001:10001

# 容器内必须绑 0.0.0.0，否则 kube-proxy 转发不进来。
ENV BIND_ADDR=0.0.0.0:3000
EXPOSE 3000

ENTRYPOINT ["/taptap-rback"]
