from collections import Counter
import string

CIPHER_1 = """af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eao--wvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvc--pfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnir--ceiki tdvng pc niprc kiopaf dfi mddg oafg cepc tdvng qdfcafvi cei kiripkqe"""

CIPHER_2 = """aceah toz puvg vcdl omj puvg yudqecov, omj loj auum klu thmjuv hs klu zlcvu shv zcbkg guovz, upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm. klu vcdluz lu loj avhqnlk aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumj, omj ck toz yhyqeoveg auecupuj, tlokupuv klu hej sher wcnlk zog, klok klu lcee ok aon umj toz sqee hs kqmmuez zkqssuj tckl kvuozqvu. omj cs klok toz mhk umhqnl shv sowu, kluvu toz oezh lcz yvhehmnuj pcnhqv kh wovpue ok. kcwu thvu hm, aqk ck zuuwuj kh lopu eckkeu ussudk hm wv. aonncmz. ok mcmukg lu toz wqdl klu zowu oz ok scskg. ok mcmukg-mcmu klug aunom kh doee lcw tuee-yvuzuvpuj; aqk qmdlomnuj thqej lopu auum muovuv klu wovr. kluvu tuvu zhwu klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn; ck zuuwuj qmsocv klok omghmu zlhqej yhzzuzz (oyyovumkeg) yuvyukqoe ghqkl oz tuee oz (vuyqkujeg) cmubloqzkcaeu tuoekl. ck tcee lopu kh au yocj shv, klug zocj. ck czm'k mokqvoe, omj kvhqaeu tcee dhwu hs ck! aqk zh sov kvhqaeu loj mhk dhwu; omj oz wv. aonncmz toz numuvhqz tckl Icz whmug, whzk yuhyeu tuvu tceecmn kh shvncpu lcw Icz hjjckcuz omj Icz nhhj shvkqmu. lu vuwocmuj hm pczckcmn kuvwz tckl Icz vueokcpuz (ubduyk, hs dhqvzu, klu zodrpceeu- aonncmzuz), omj lu loj womg juphkuj ojwcvuvz owhmn klu lhaackz hs yhhv omj qmcwyhvkomk sowcecuz. aqk lu loj mh dehzu svcumjz, qmkce zhwu hs Icz ghqmnuv dhqzcmz aunom kh nvht qy. klu uejuzk hs kluzu, omj aceah'z sophqvcku, toz ghqmn svhjh aonncmz. tlum aceah toz mcmukg-mcmu lu ojhykuj svhjh oz Icz lucv, omj avhqnlk Icw kh ecpu ok aon umj; omj klu lhyuz hs klu zodrpceeu- aonncmzuz tuvu scmoeeg jozluj. aceah omj svhjh loyyumuj kh lopu klu zowu acvkljog, zuykuwauv 22mj. ghq loj aukkuv dhwu omj ecpu luvu, svhjh wg eoj, zocj aceah hmu jog; omj klum tu dom dueuavoku hqv acvkljog-yovkcuz dhwshvkoaeg khnukluv. ok klok kcwu svhjh toz zkcee cm Icz ktuumz, oz klu lhaackz doeeuj klu cvvuzyhmzcaeu ktumkcuz auktuum dlcejlhhj omj dhwcmn hs onu ok klcvkg-klvuu"""

ENGLISH_FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"


def calculate_char_frequency(text: str):
    """Return list of (char, count, percentage) sorted by percentage desc."""
    text_low = text.lower()
    counts = Counter(ch for ch in text_low if ch.isalpha())
    total = sum(counts.values()) or 1
    freqs = [(ch, counts[ch], (counts[ch] / total) * 100) for ch in counts]
    freqs.sort(key=lambda x: x[2], reverse=True)
    return freqs


def initial_guess_mapping_by_frequency(ciphertext: str, english_order: str = ENGLISH_FREQ_ORDER):
    freqs = calculate_char_frequency(ciphertext)
    cipher_sorted = [ch for ch, _, _ in freqs]
    mapping = {}
    for i, c in enumerate(cipher_sorted):
        if i < len(english_order):
            mapping[c] = english_order[i]
    return mapping


def apply_mapping(ciphertext: str, mapping: dict, placeholder: str = '_'):
    out = []
    for ch in ciphertext:
        if ch.isalpha():
            low = ch.lower()
            plain = mapping.get(low, placeholder)
            out.append(plain.upper() if ch.isupper() else plain)
        else:
            out.append(ch)
    return ''.join(out)


def update_mapping(mapping: dict, cipher_letter: str, plain_letter: str):
    mapping[cipher_letter.lower()] = plain_letter.lower()
    return mapping


def pretty_print_freq_table(freqs):
    print("Char | Count | Percent")
    print("----------------------")
    for ch, cnt, pct in freqs:
        print(f"  {ch}  |  {cnt:5d} |  {pct:6.2f}%")
    print()


def invert_key_map(mapping):
    inv = {}
    for c, p in mapping.items():
        inv.setdefault(p, []).append(c)
    return inv



def example_run():
    print("=== Cipher 1 analysis ===")
    freq1 = calculate_char_frequency(CIPHER_1)
    pretty_print_freq_table(freq1)

    print("Initial guess mapping (by frequency):")
    init_map1 = initial_guess_mapping_by_frequency(CIPHER_1)
    print(init_map1)
    print("\nInitial decryption (underscores = unmapped):")
    print(apply_mapping(CIPHER_1, init_map1))

    final_key_map_cipher1 = {
        'a': 'i', 'c': 't', 'd': 'o', 'e': 'h', 'f': 'n', 'g': 'd', 'h': 'b',
        'i': 'e', 'j': 'q', 'k': 'r', 'l': 'k', 'm': 'g', 'n': 'l', 'o': 'm',
        'p': 'a', 'q': 'c', 'r': 's', 's': 'j', 't': 'w', 'u': 'f',
        'v': 'u', 'w': 'y', 'x': 'p'
    }
    print("\nFinal mapping (cipher->plain) for Cipher-1:")
    for k in sorted(final_key_map_cipher1):
        print(f"  {k} -> {final_key_map_cipher1[k]}")
    print("\nFinal decryption for Cipher-1:")
    print(apply_mapping(CIPHER_1, final_key_map_cipher1, placeholder='_'))

    # --- Cipher 2 ---
    print("\n\n=== Cipher 2 analysis ===")
    freq2 = calculate_char_frequency(CIPHER_2)
    pretty_print_freq_table(freq2)

    print("Initial guess mapping (by frequency):")
    init_map2 = initial_guess_mapping_by_frequency(CIPHER_2)
    print(init_map2)
    print("\nInitial decryption (underscores = unmapped):")
    print(apply_mapping(CIPHER_2, init_map2))

    final_key_map_cipher2 = {
        'u': 'e', 'k': 't', 'l': 'h', 't': 'w', 'o': 'a', 'z': 's',
        'm': 'n', 'j': 'd', 'v': 'r', 'c': 'i', 'd': 'c', 'p': 'v',
        'g': 'y', 'y': 'p', 'q': 'u', 'e': 'l', 'w': 'm', 'r': 'k',
        'a': 'b', 'b': 'x', 'h': 'o', 's': 'f', 'n': 'g', 'i': 'j'
    }
    print("\nFinal mapping (cipher->plain) for Cipher-2:")
    for k in sorted(final_key_map_cipher2):
        print(f"  {k} -> {final_key_map_cipher2[k]}")
    print("\nFinal decryption for Cipher-2:")
    print(apply_mapping(CIPHER_2, final_key_map_cipher2, placeholder='_'))

    print("\nCollision check for Cipher-2 mapping (plain -> cipher letters):")
    inv2 = invert_key_map(final_key_map_cipher2)
    for plain, ciphers in sorted(inv2.items()):
        if len(ciphers) > 1:
            print(f"  WARNING: plain '{plain}' mapped from multiple cipher letters: {ciphers}")
        else:
            print(f"  '{plain}' <- {ciphers[0]}")

if __name__ == "__main__":
    example_run()
