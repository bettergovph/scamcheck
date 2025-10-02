// esbuild configuration to support importing HTML files as text
export default {
  loader: {
    '.html': 'text',
  },
};
