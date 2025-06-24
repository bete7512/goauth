package repositories

import (
	"testing"
)

func BenchmarkUserRepositoryCreate(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// TODO: Add actual repository benchmark
		_ = i
	}
}

func BenchmarkUserRepositoryFindByEmail(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// TODO: Add actual repository benchmark
		_ = i
	}
}

func BenchmarkTokenRepositoryCreate(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// TODO: Add actual repository benchmark
		_ = i
	}
}
