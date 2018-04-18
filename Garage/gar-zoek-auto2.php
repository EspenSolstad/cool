<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="author " content="Espen Solstad">
    <meta charset="UTF-8">
    <title>GCS</title>
</head>
<body>
<h1>Garage Car Searcher</h1>
<p>
    This form searched for a specific car in the database using the corresponding License plate.
</p>
<?php
$autokenteken = $_POST["autokentekenvak"];

require_once "gar-connect.php";

$sql = $conn->prepare("
                                    select  autokenteken,
                                                automerk,
                                                autotype,
                                                autokmstand,
                                                klantid
                                        from    auto
                                        where   autokenteken = :autokenteken
                                      ");
$sql->execute(["autokenteken" => $autokenteken]);


echo "<table>";
foreach ($sql as $rij)
{
    echo "<tr>";
    echo "<td>"  . $rij["autokenteken"]       . "</td>";
    echo "<td>"  . $rij["automerk"]     . "</td>";
    echo "<td>"  . $rij["autotype"]    . "</td>";
    echo "<td>"  . $rij["autokmstand"] . "</td>";
    echo "<td>"  . $rij["klantid"]   . "</td>";
    echo "</tr>";
}
echo "</table>";
echo "<a href='gar-menu.php'>Back to the GDM</a>";
?>
</body>
</html>