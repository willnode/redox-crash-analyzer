import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import babel from "vite-plugin-babel";
import commonjs from 'vite-plugin-commonjs'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    // babel({
    //   babelConfig: {
    //     plugins: ["transform-amd-to-commonjs"],
    //   },
    // }),
    // commonjs(),
    vue()],
})
