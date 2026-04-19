const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('App root not found.');
}

app.innerHTML = `
  <main>
    <h1>crypto-lab-hawk</h1>
    <p>Educational HAWK signature demo scaffold in progress.</p>
  </main>
`;