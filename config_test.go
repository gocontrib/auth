package auth

func makeTestConfig() *Config {
	store := makeTestUserStore()

	return &Config{
		UserStore: store,
	}
}
