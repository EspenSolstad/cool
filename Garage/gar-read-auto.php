<!DOCTYPE html>
<html lang="nl">
<head>
    <meta name="author " content="Espen Solstad">
    <meta charset="UTF-8">
    <title>GCR</title>
</head>
<body>
<h1>Garage Car Reader</h1>
<p>
    All Car data.
</p>
<?php
require_once "gar-connect.php";

$sql = $conn->prepare("
                                        select  autokenteken,
                                                automerk,
                                                autotype,
                                                autokmstand,
                                                klantid
                                        from    auto
                                        ");
$sql->execute();

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