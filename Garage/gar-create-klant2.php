<!DOCTYPE html>
<html lang="nl">
<head>
    <meta name="author " content="Espen Solstad">
    <meta charset="UTF-8">
    <title>gar-create-klant2.php</title>
</head>
<body>
    <h1>garage create klant 2</h1>
    <p>
        Een klant toevoegen aan de tabel
        klant in de database garage.
    </p>
    <?php
    // klantgegevens uit de formulier halen --------------------------
    $klantid         = NULL;
    $klantnaam       = $_POST["klantnaamvak"];
    $klantadres      = $_POST["klantadresvak"];
    $klantpostcode   = $_POST["klantpostcodevak"];
    $klantplaats     = $_POST["klantplaatsvak"];

    // klantgegevens invoeren in de tabel-----------------------------
    require_once "gar-connect.php";

    $sql = $conn->prepare("
                                    insert into klant values
                                    (
                                        :klantid, :klantnaam, :klantadres,
                                        :klantpostcode, :klantplaats
                                    )
                                 ");

    $sql->execute([
                    "klantid"        => $klantid,
                    "klantnaam"      => $klantnaam,
                    "klantadres"     => $klantadres,
                    "klantpostcode"  => $klantpostcode,
                    "klantplaats"    => $klantplaats
                  ]);
    echo "De klant is toegevoegd <br />";
    echo "<a href='gar-menu.php'>Back to the GDM</a>";
    ?>
</body>
</html>