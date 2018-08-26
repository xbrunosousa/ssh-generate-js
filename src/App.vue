<template>
  <div id="app">
    <sshComponent />
  </div>
</template>

<script>
import sshComponent from './components/ssh-component.vue';

export default {
  name: 'app',
  components: {
    sshComponent
  }
};
</script>

<style lang="scss">
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
