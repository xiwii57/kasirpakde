import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import vercel from '@astrojs/vercel';

export default defineConfig({
  output: 'server',
  adapter: vercel(),

                            // Domain utama aplikasi
                            site: 'https://www.karsip.my.id',

                            security: {
                              // Diatur ke false karena sudah mengimplementasikan
                              // pengecekan Origin manual yang sangat ketat di middleware.ts
                              checkOrigin: false,
                            },

                            devToolbar: {
                              enabled: false,
                            },

                            vite: {
                              plugins: [tailwindcss()],
                            },
});
