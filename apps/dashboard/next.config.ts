import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@aegis/shared", "@aegis/phantom"],
  output: "standalone",
};

export default nextConfig;
