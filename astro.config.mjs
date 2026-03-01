import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import vercel from '@astrojs/vercel';

export default defineConfig({
  output: 'server',
  adapter: vercel(),

                            // Domain utama aplikasi
                            site: 'https://www.karsip.my.id',

                            security: {
                              // Diatur ke false karena kamu sudah mengimplementasikan
                              // pengecekan Origin manual yang sangat ketat di middleware.ts
                              checkOrigin: false,
                            },

                            prefetch: {
                              prefetchAll: true,
                            defaultStrategy: 'viewport',
                            },

                            devToolbar: {
                              enabled: false,
                            },

                            vite: {
                              plugins: [tailwindcss()],
                            },
});
