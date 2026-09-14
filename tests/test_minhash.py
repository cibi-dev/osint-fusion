def test_identical_texts_similarity(hasher):
    text1 = "Suspicious financial transaction from account A to domain B"
    text2 = "Suspicious financial transaction from account A to domain B"
    sh1 = hasher.shingle(text1)
    sh2 = hasher.shingle(text2)
    sig1 = hasher.compute_signature(sh1)
    sig2 = hasher.compute_signature(sh2)
    sim = hasher.estimate_jaccard(sig1, sig2)
    assert sim == 1.0

def test_different_texts_similarity(hasher):
    text1 = "Alpha bravo charlie delta echo"
    text2 = "Zoo zebra quartz xylophone whisper"
    sh1 = hasher.shingle(text1)
    sh2 = hasher.shingle(text2)
    sig1 = hasher.compute_signature(sh1)
    sig2 = hasher.compute_signature(sh2)
    sim = hasher.estimate_jaccard(sig1, sig2)
    assert sim < 0.2
