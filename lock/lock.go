package lock

type Lock interface {
	Lock(string)
	Unlock(string)
}
