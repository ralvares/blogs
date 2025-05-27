package main

approved_prefixes := [
  "quay.myorg.com/approved/",
  "quay.anotherorg.com/trusted/"
]

deny contains msg if {
  some i
  input[i].Cmd == "from"
  from := input[i].Value[0]
  not startswith_any(from, approved_prefixes)
  msg := sprintf("Unapproved base image: %s", [from])
}

startswith_any(str, prefixes) if {
  some i
  startswith(str, prefixes[i])
}
