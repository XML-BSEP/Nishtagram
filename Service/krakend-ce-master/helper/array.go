package helper

func ContainsElement(array []string, element string) bool {
	for _, elem := range array {
		if elem == element {
			return true
		}
	}
	return false
}
