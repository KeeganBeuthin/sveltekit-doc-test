<script>
  import { page } from '$app/stores';
  export let data;
</script>

<div class="app">
  <header>
    <nav>
      <a href="/">Home</a>
      
      {#if data.authenticated}
        <a href="/dashboard">Dashboard</a>
        <a href="/api/auth/logout" class="logout">Logout</a>
      {:else}
        <a href="/api/auth/login">Login</a>
      {/if}
    </nav>
  </header>
  
  <main>
    <slot />
  </main>
  
  <footer>
    <p>SvelteKit with Kinde Authentication</p>
  </footer>
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }
  
  header {
    background-color: #f9fafb;
    border-bottom: 1px solid #e5e7eb;
    padding: 1rem;
  }
  
  nav {
    display: flex;
    gap: 1rem;
    max-width: 1200px;
    margin: 0 auto;
  }
  
  a {
    color: #4f46e5;
    text-decoration: none;
    font-weight: 500;
  }
  
  a:hover {
    text-decoration: underline;
  }
  
  .logout {
    margin-left: auto;
    color: #ef4444;
  }
  
  main {
    flex: 1;
  }
  
  footer {
    background-color: #f9fafb;
    border-top: 1px solid #e5e7eb;
    padding: 1rem;
    text-align: center;
    color: #6b7280;
  }
</style> 