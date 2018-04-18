<!DOCTYPE html>
<html lang="nl">
    <head>
        <meta name="author " content="Espen Solstad">
        <meta charset="UTF-8">
        <title>GCR</title>
    </head>
<body>
    <h1>Garage Customer Reader</h1>
    <p>
        This is all Customer Data
    </p>
    <?php
    require_once "gar-connect.php";

        $sql = $conn->prepare("
                                        select  klantid,
                                                klantnaam,
                                                klantadres,
                                                klantpostcode,
                                                klantplaats
                                        from    klant
                                        ");
        $sql->execute();

    echo "<table>";
        foreach ($sql as $rij)
        {
            echo "<tr>";
            echo "<td>"  . $rij["klantid"]       . "</td>";
            echo "<td>"  . $rij["klantnaam"]     . "</td>";
            echo "<td>"  . $rij["klantadres"]    . "</td>";
            echo "<td>"  . $rij["klantpostcode"] . "</td>";
            echo "<td>"  . $rij["klantplaats"]   . "</td>";
            echo "</tr>";
        }
        echo "</table>";
        echo "<a href='gar-menu.php'>Back to the GDM</a>";
    ?>
</body>
</html>